package com.postlock.boot;

import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

/**
 * Minimal ADB protocol client for the local loopback bootstrap.
 *
 * The PostLock app (untrusted_app) cannot run the exploit chain itself:
 * tracefs, the mm_struct timing scan and configfs are all SELinux/strace
 * denied in that domain (2026-10-20 verdict).  The chain therefore runs
 * with SHELL uid through adbd's TCP listener on 127.0.0.1:5555, which is
 * provisioned once by tools/postlock.sh (persist.adb.tcp.port protobuf
 * entry + this app's pubkey in /data/misc/adb/adb_keys).  We speak the
 * classic plaintext adb transport: CNXN, AUTH (RSA-SHA1 over the 20-byte
 * token), then OPEN a "shell,v2:" stream carrying stdout/stderr/exit
 * frames.
 *
 * One instance == one TCP connection; every call is synchronous.  All
 * commands take a fresh connection (loopback connect+auth is ~5 ms) which
 * keeps the class stateless and immune to adbd idle teardown races.
 */
public final class AdbShell implements Closeable {

    public static final class Result {
        public final int exit;
        public final String stdout;
        public final String stderr;

        Result(int exit, String stdout, String stderr) {
            this.exit = exit;
            this.stdout = stdout;
            this.stderr = stderr;
        }

        public String out() {
            return stdout == null ? "" : stdout;
        }

        @Override
        public String toString() {
            return "exit=" + exit + " out=" + out().trim();
        }
    }

    /** adb wire commands, compared/produced as literal ASCII. */
    private static final byte[][] CMDS = {
            "CNXN".getBytes(StandardCharsets.US_ASCII),
            "AUTH".getBytes(StandardCharsets.US_ASCII),
            "OPEN".getBytes(StandardCharsets.US_ASCII),
            "OKAY".getBytes(StandardCharsets.US_ASCII),
            "CLSE".getBytes(StandardCharsets.US_ASCII),
            "WRTE".getBytes(StandardCharsets.US_ASCII),
    };
    private static final int CNXN = 0, AUTH = 1, OPEN = 2, OKAY = 3, CLSE = 4, WRTE = 5;

    /** AUTH arg0 types. */
    private static final int AUTH_TOKEN = 1;
    private static final int AUTH_SIGNATURE = 2;
    private static final int AUTH_RSAPUBLICKEY = 3;

    /** shell v2 frame ids. */
    private static final int SH_STDIN = 0;
    private static final int SH_STDOUT = 1;
    private static final int SH_STDERR = 2;
    private static final int SH_EXIT = 3;
    private static final int SH_CLOSE = 4;

    private static final int A_VERSION = 0x01000001;
    private static final int DEFAULT_MAX_DATA = 262144;

    private Socket sock;
    private InputStream in;
    private OutputStream out;
    private int maxData = DEFAULT_MAX_DATA;
    private int nextLocalId = 1;
    private final PrivateKey key;
    private final byte[] pubBlob;

    private AdbShell(PrivateKey key, byte[] pubBlob) {
        this.key = key;
        this.pubBlob = pubBlob;
    }

    // --- key loading -------------------------------------------------------

    /** PKCS#8 PEM ("BEGIN PRIVATE KEY") from assets/postlock/. */
    public static PrivateKey loadPrivateKey(String pemText) throws Exception {
        String body = pemText
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(body);
        return KeyFactory.getInstance("RSA")
                .generatePrivate(new PKCS8EncodedKeySpec(der));
    }

    /**
     * AUTH RSAPUBLICKEY payload: "&lt;b64&gt; &lt;comment&gt;\0" using the
     * .pub file content (already in adb's "2048 b64 name" format).
     */
    public static byte[] publicBlob(String pubText) {
        String s = pubText.trim();
        byte[] b = s.getBytes(StandardCharsets.UTF_8);
        byte[] z = new byte[b.length + 1];
        System.arraycopy(b, 0, z, 0, b.length);
        return z;
    }

    // --- lifecycle ---------------------------------------------------------

    /** Connect + CNXN/AUTH handshake; throws when adbd never sends CNXN. */
    public AdbShell connect(String host, int port) throws IOException {
        sock = new Socket();
        try {
            sock.connect(new InetSocketAddress(host, port), 8000);
            sock.setSoTimeout(12000);
            in = sock.getInputStream();
            out = sock.getOutputStream();
        } catch (IOException e) {
            close();
            throw e;
        }
        try {
            handshake();
        } catch (IOException | RuntimeException e) {
            close();
            throw e;
        } catch (Exception e) {
            close();
            throw new IOException("auth: " + e, e);
        }
        return this;
    }

    private void handshake() throws Exception {
        send(CNXN, A_VERSION, DEFAULT_MAX_DATA, "host::".getBytes(StandardCharsets.UTF_8));
        int tokens = 0;
        for (int i = 0; i < 10; i++) {
            Msg m = recv();
            if (m.cmd == CNXN) {
                maxData = Math.min(DEFAULT_MAX_DATA, Math.max(4096, m.arg1));
                Log.i(PostLock.TAG, "adb CNXN maxdata=" + m.arg1
                        + " banner=" + new String(m.data, StandardCharsets.US_ASCII));
                return;
            }
            if (m.cmd == AUTH && m.arg0 == AUTH_TOKEN && m.data.length == 20) {
                tokens++;
                if (tokens == 1) {
                    Signature sig = Signature.getInstance("SHA1withRSA");
                    sig.initSign(key);
                    sig.update(m.data);
                    send(AUTH, AUTH_SIGNATURE, 0, sig.sign());
                } else if (tokens <= 3 && pubBlob != null) {
                    send(AUTH, AUTH_RSAPUBLICKEY, 0, pubBlob);
                } else {
                    throw new IOException("adbd rejected all auth attempts");
                }
                continue;
            }
            // anything else before CNXN (SYNC etc.) is ignorable
        }
        throw new IOException("no CNXN from adbd (not authorized?)");
    }

    /**
     * Run one command through a fresh "shell,v2:" stream on this
     * connection.  Serial only (synchronized); reuses the transport.
     * Completion: EXIT frame records the code, the adbd-side CLSE that
     * follows it ends the loop.
     */
    public synchronized Result exec(String cmd, long timeoutMs) throws IOException {
        if (sock == null || sock.isClosed()) {
            throw new IOException("not connected");
        }
        pendingExit = -1;
        int localId = nextLocalId++;
        byte[] dest = ("shell,v2:" + cmd).getBytes(StandardCharsets.UTF_8);
        if (dest.length > maxData) {
            throw new IOException("command too long: " + dest.length + " > " + maxData);
        }
        send(OPEN, localId, 0, dest);

        ByteArrayOutputStream stdout = new ByteArrayOutputStream();
        ByteArrayOutputStream stderr = new ByteArrayOutputStream();
        boolean closed = false;
        long deadline = System.currentTimeMillis() + timeoutMs;
        int remoteId = -1;

        while (!closed) {
            long remain = deadline - System.currentTimeMillis();
            if (remain <= 0) {
                throw new SocketTimeoutException("exec timeout: " + cmd);
            }
            Msg m;
            try {
                sock.setSoTimeout((int) Math.min(12000, Math.max(1, remain)));
                m = recv();
            } catch (SocketTimeoutException te) {
                if (System.currentTimeMillis() >= deadline) {
                    throw te;
                }
                continue;
            }
            switch (m.cmd) {
                case OKAY:
                    if (m.arg1 == localId) {
                        remoteId = m.arg0;
                    }
                    break;
                case WRTE:
                    if (m.arg1 != localId || remoteId < 0) {
                        break;
                    }
                    remoteId = m.arg0;
                    // ack first: adbd blocks the next frame until OKAY
                    send(OKAY, localId, remoteId, null);
                    parseShellFrames(m.data, stdout, stderr);
                    break;
                case CLSE:
                    if (m.arg1 == localId || remoteId < 0) {
                        closed = true;
                        if (m.arg0 > 0) {
                            try {
                                send(CLSE, localId, m.arg0, null);
                            } catch (IOException ignored) {
                            }
                        }
                    }
                    break;
                default:
                    break;
            }
        }
        return new Result(pendingExit, stdout.toString("UTF-8"), stderr.toString("UTF-8"));
    }

    private int pendingExit = -1;

    private void parseShellFrames(byte[] data, ByteArrayOutputStream stdout,
                                  ByteArrayOutputStream stderr) {
        int off = 0;
        while (off + 5 <= data.length) {
            int id = data[off] & 0xff;
            int len = ((data[off + 1] & 0xff) << 24) | ((data[off + 2] & 0xff) << 16)
                    | ((data[off + 3] & 0xff) << 8) | (data[off + 4] & 0xff);
            off += 5;
            if (len < 0 || off + len > data.length) {
                break; // malformed; keep what we have
            }
            switch (id) {
                case SH_STDOUT:
                    stdout.write(data, off, len);
                    break;
                case SH_STDERR:
                    stderr.write(data, off, len);
                    break;
                case SH_EXIT:
                    if (len >= 4) {
                        pendingExit = ((data[off] & 0xff) << 24) | ((data[off + 1] & 0xff) << 16)
                                | ((data[off + 2] & 0xff) << 8) | (data[off + 3] & 0xff);
                    }
                    break;
                case SH_CLOSE:
                case SH_STDIN:
                default:
                    break;
            }
            off += len;
        }
    }

    /** Convenience: fresh connection, one command, close. */
    public static Result runOnce(String host, int port, PrivateKey key, byte[] pub,
                                 String cmd, long timeoutMs) throws IOException {
        try (AdbShell s = new AdbShell(key, pub).connect(host, port)) {
            return s.exec(cmd, timeoutMs);
        }
    }

    @Override
    public void close() {
        if (sock != null) {
            try {
                sock.close();
            } catch (IOException ignored) {
            }
            sock = null;
        }
    }

    // --- wire --------------------------------------------------------------

    private static final class Msg {
        int cmd;
        int arg0;
        int arg1;
        byte[] data;
    }

    private void send(int cmdIdx, int arg0, int arg1, byte[] data) throws IOException {
        byte[] d = data == null ? new byte[0] : data;
        byte[] cmd = CMDS[cmdIdx];
        int cmdInt = (cmd[0] & 0xff) | ((cmd[1] & 0xff) << 8)
                | ((cmd[2] & 0xff) << 16) | ((cmd[3] & 0xff) << 24);
        byte[] h = new byte[24];
        putLe32(h, 0, cmdInt);
        putLe32(h, 4, arg0);
        putLe32(h, 8, arg1);
        putLe32(h, 12, d.length);
        putLe32(h, 16, 0); // crc unused at A_VERSION >= 0x01000000
        putLe32(h, 20, ~cmdInt);
        synchronized (out) {
            out.write(h);
            if (d.length > 0) {
                out.write(d);
            }
            out.flush();
        }
    }

    private Msg recv() throws IOException {
        byte[] h = readFully(24);
        Msg m = new Msg();
        int cmdInt = le32(h, 0);
        m.cmd = cmdIndex(cmdInt);
        m.arg0 = le32(h, 4);
        m.arg1 = le32(h, 8);
        int len = le32(h, 12);
        int magic = le32(h, 20);
        if (m.cmd < 0 || magic != ~cmdInt) {
            throw new IOException("corrupt header cmd=" + cmdInt + " magic=" + magic);
        }
        if (len < 0 || len > 8 * 1024 * 1024) {
            throw new IOException("bad payload len " + len);
        }
        m.data = len > 0 ? readFully(len) : new byte[0];
        return m;
    }

    private static int cmdIndex(int cmdInt) {
        byte[] b = new byte[4];
        b[0] = (byte) (cmdInt);
        b[1] = (byte) (cmdInt >> 8);
        b[2] = (byte) (cmdInt >> 16);
        b[3] = (byte) (cmdInt >> 24);
        for (int i = 0; i < CMDS.length; i++) {
            if (b[0] == CMDS[i][0] && b[1] == CMDS[i][1]
                    && b[2] == CMDS[i][2] && b[3] == CMDS[i][3]) {
                return i;
            }
        }
        return -1;
    }

    private byte[] readFully(int n) throws IOException {
        byte[] b = new byte[n];
        int off = 0;
        while (off < n) {
            int r = in.read(b, off, n - off);
            if (r < 0) {
                throw new IOException("eof reading " + n + " bytes (got " + off + ")");
            }
            off += r;
        }
        return b;
    }

    private static void putLe32(byte[] b, int off, int v) {
        b[off] = (byte) v;
        b[off + 1] = (byte) (v >> 8);
        b[off + 2] = (byte) (v >> 16);
        b[off + 3] = (byte) (v >> 24);
    }

    private static int le32(byte[] b, int off) {
        return (b[off] & 0xff) | ((b[off + 1] & 0xff) << 8)
                | ((b[off + 2] & 0xff) << 16) | ((b[off + 3] & 0xff) << 24);
    }
}
