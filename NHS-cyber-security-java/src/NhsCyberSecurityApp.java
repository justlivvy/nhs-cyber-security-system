import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class NhsCyberSecurityApp {
    private static final DateTimeFormatter TIME_FORMAT = DateTimeFormatter.ofPattern("HH:mm:ss");
    private static final DateTimeFormatter DATA_TIME_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final Path WEB_ROOT = Path.of("web").toAbsolutePath().normalize();
    private static final SecureRandom RANDOM = new SecureRandom();

    private final List<String> logs = new ArrayList<>();
    private final Map<String, StaffUser> users = new LinkedHashMap<>();
    private Path loginDatabase;

    public NhsCyberSecurityApp(Path loginDatabase) {
        this.loginDatabase = loginDatabase.toAbsolutePath().normalize();
    }

    public static void main(String[] args) throws IOException {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 8080;
        Path database = args.length > 1 ? Path.of(args[1]) : Path.of("data", "logins.csv");
        new NhsCyberSecurityApp(database).start(port);
    }

    private void start(int port) throws IOException {
        try {
            loadLoginDatabase();
        } catch (IOException error) {
            Path requestedDatabase = loginDatabase;
            users.clear();
            loginDatabase = Path.of(System.getProperty("java.io.tmpdir"), "nhs-cyber-security-logins.csv");
            loadLoginDatabase();
            addLog("Project database was read-only, using temp database instead of " + requestedDatabase);
        }
        addLog("Java server started on port " + port);
        addLog("Login database connected: " + loginDatabase);

        HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", port), 0);
        server.createContext("/api/register", this::handleRegister);
        server.createContext("/api/login", this::handleLogin);
        server.createContext("/api/biometric", this::handleBiometric);
        server.createContext("/api/logs", this::handleLogs);
        server.createContext("/api/database", this::handleDatabase);
        server.createContext("/api/legacy-breach", this::handleLegacyBreach);
        server.createContext("/", this::handleStaticFile);
        server.setExecutor(null);
        server.start();

        System.out.println("NHS Cyber Security demo running on port " + port);
    }

    private void loadLoginDatabase() throws IOException {
        Files.createDirectories(loginDatabase.getParent());
        if (!Files.exists(loginDatabase)) {
            seedDefaultLogin();
            saveLoginDatabase();
            return;
        }

        List<String> lines = Files.readAllLines(loginDatabase, StandardCharsets.UTF_8);
        for (int i = 1; i < lines.size(); i++) {
            if (lines.get(i).isBlank()) {
                continue;
            }
            StaffUser user = StaffUser.fromCsv(lines.get(i));
            users.put(user.username, user);
        }

        if (users.isEmpty()) {
            seedDefaultLogin();
            saveLoginDatabase();
        }
    }

    private void seedDefaultLogin() {
        try {
            StaffUser user = StaffUser.create("nhs.staff", "NHS Staff Demo", "Clinical Staff", "NHSdemo123!");
            users.put(user.username, user);
        } catch (GeneralSecurityException error) {
            throw new IllegalStateException("Could not seed default login", error);
        }
    }

    private void saveLoginDatabase() throws IOException {
        List<String> lines = new ArrayList<>();
        lines.add("username,fullName,role,salt,passwordHash,credentialID,publicKey,createdAt,lastLogin");
        for (StaffUser user : users.values()) {
            lines.add(user.toCsv());
        }
        Files.write(loginDatabase, lines, StandardCharsets.UTF_8);
    }

    private void handleRegister(HttpExchange exchange) throws IOException {
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendText(exchange, 405, "Method not allowed", "text/plain");
            return;
        }

        Map<String, String> body = parseJsonBody(exchange);
        String username = clean(body.get("username")).toLowerCase();
        String fullName = clean(body.get("fullName"));
        String role = clean(body.get("role"));
        String password = body.getOrDefault("password", "");

        if (username.isBlank() || fullName.isBlank() || role.isBlank() || password.length() < 8) {
            sendJson(exchange, 400, "{\"status\":\"error\",\"message\":\"Enter a name, role, username, and password of at least 8 characters.\"}");
            return;
        }
        if (users.containsKey(username)) {
            sendJson(exchange, 409, "{\"status\":\"error\",\"message\":\"That username already exists.\"}");
            return;
        }

        try {
            StaffUser user = StaffUser.create(username, fullName, role, password);
            users.put(username, user);
            saveLoginDatabase();
            addLog("Registered login for " + username);
            sendJson(exchange, 201, "{\"status\":\"success\",\"message\":\"Account created\",\"user\":\"" + escapeJson(username) + "\"}");
        } catch (GeneralSecurityException error) {
            sendJson(exchange, 500, "{\"status\":\"error\",\"message\":\"Could not secure password.\"}");
        }
    }

    private void handleLogin(HttpExchange exchange) throws IOException {
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendText(exchange, 405, "Method not allowed", "text/plain");
            return;
        }

        Map<String, String> body = parseJsonBody(exchange);
        String username = clean(body.get("username")).toLowerCase();
        String password = body.getOrDefault("password", "");
        StaffUser user = users.get(username);

        try {
            if (user == null || !user.matchesPassword(password)) {
                addLog("Failed login attempt for " + username);
                sendJson(exchange, 401, "{\"status\":\"error\",\"message\":\"Username or password is incorrect.\"}");
                return;
            }

            user.lastLogin = nowForData();
            saveLoginDatabase();
            addLog("Password login success for " + username);
            sendJson(exchange, 200, "{\"status\":\"success\",\"message\":\"Login successful\",\"user\":\"" +
                    escapeJson(user.username) + "\",\"fullName\":\"" + escapeJson(user.fullName) + "\",\"role\":\"" +
                    escapeJson(user.role) + "\"}");
        } catch (GeneralSecurityException error) {
            sendJson(exchange, 500, "{\"status\":\"error\",\"message\":\"Could not verify password.\"}");
        }
    }

    private void handleBiometric(HttpExchange exchange) throws IOException {
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendText(exchange, 405, "Method not allowed", "text/plain");
            return;
        }

        Map<String, String> body = parseJsonBody(exchange);
        String username = clean(body.get("username")).toLowerCase();
        StaffUser user = users.get(username);
        if (user == null) {
            sendJson(exchange, 404, "{\"status\":\"error\",\"message\":\"Login first so the biometric can link to a staff account.\"}");
            return;
        }

        if (user.credentialID.isBlank()) {
            user.credentialID = "NHS-" + randomToken(8);
            user.publicKey = "PUB-" + randomToken(14);
            saveLoginDatabase();
            addLog("Biometric credential registered for " + username);
            sendJson(exchange, 200, "{\"status\":\"success\",\"message\":\"Biometric registered\",\"user\":\"" + escapeJson(username) + "\"}");
            return;
        }

        user.lastLogin = nowForData();
        saveLoginDatabase();
        addLog("Biometric login success for " + username);
        sendJson(exchange, 200, "{\"status\":\"success\",\"message\":\"Biometric login successful\",\"user\":\"" + escapeJson(username) + "\"}");
    }

    private void handleLogs(HttpExchange exchange) throws IOException {
        if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendText(exchange, 405, "Method not allowed", "text/plain");
            return;
        }

        StringBuilder json = new StringBuilder("{\"logs\":[");
        for (int i = 0; i < logs.size(); i++) {
            if (i > 0) {
                json.append(',');
            }
            json.append('"').append(escapeJson(logs.get(i))).append('"');
        }
        json.append("]}");
        sendJson(exchange, 200, json.toString());
    }

    private void handleDatabase(HttpExchange exchange) throws IOException {
        if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendText(exchange, 405, "Method not allowed", "text/plain");
            return;
        }

        StringBuilder json = new StringBuilder("{\"users\":[");
        int i = 0;
        for (StaffUser user : users.values()) {
            if (i++ > 0) {
                json.append(',');
            }
            json.append("{\"username\":\"").append(escapeJson(user.username))
                    .append("\",\"fullName\":\"").append(escapeJson(user.fullName))
                    .append("\",\"role\":\"").append(escapeJson(user.role))
                    .append("\",\"credentialID\":\"").append(escapeJson(displayOrPending(user.credentialID)))
                    .append("\",\"publicKey\":\"").append(escapeJson(displayOrPending(user.publicKey)))
                    .append("\",\"passwordHash\":\"").append(escapeJson(shortHash(user.passwordHash)))
                    .append("\",\"createdAt\":\"").append(escapeJson(user.createdAt))
                    .append("\",\"lastLogin\":\"").append(escapeJson(displayOrPending(user.lastLogin)))
                    .append("\"}");
        }
        json.append("],\"database\":\"").append(escapeJson(loginDatabase.toString()))
                .append("\",\"note\":\"Passwords are stored as salted PBKDF2 hashes, not plain text.\"}");
        sendJson(exchange, 200, json.toString());
    }

    private void handleLegacyBreach(HttpExchange exchange) throws IOException {
        if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendText(exchange, 405, "Method not allowed", "text/plain");
            return;
        }

        sendJson(exchange, 200,
                "{\"users\":[{\"id\":1,\"user\":\"doctorA\",\"biometric_hash\":\"9AFK2939AF...\"}," +
                        "{\"id\":2,\"user\":\"nurseB\",\"biometric_hash\":\"3FAK9929AA...\"}]," +
                        "\"status\":\"Legacy honeypot system compromised\"}");
    }

    private void handleStaticFile(HttpExchange exchange) throws IOException {
        if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendText(exchange, 405, "Method not allowed", "text/plain");
            return;
        }

        URI uri = exchange.getRequestURI();
        String requestPath = URLDecoder.decode(uri.getPath(), StandardCharsets.UTF_8);
        if (requestPath.equals("/")) {
            requestPath = "/index.html";
        }

        Path file = WEB_ROOT.resolve(requestPath.substring(1)).normalize();
        if (!file.startsWith(WEB_ROOT) || !Files.exists(file) || Files.isDirectory(file)) {
            sendText(exchange, 404, "Not found", "text/plain");
            return;
        }

        sendText(exchange, 200, Files.readString(file), contentType(file));
    }

    private Map<String, String> parseJsonBody(HttpExchange exchange) throws IOException {
        String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        Map<String, String> values = new LinkedHashMap<>();
        String[] fields = {"username", "password", "fullName", "role"};
        for (String field : fields) {
            values.put(field, jsonValue(body, field));
        }
        return values;
    }

    private String jsonValue(String json, String field) {
        String marker = "\"" + field + "\"";
        int fieldStart = json.indexOf(marker);
        if (fieldStart < 0) {
            return "";
        }
        int colon = json.indexOf(':', fieldStart + marker.length());
        int valueStart = json.indexOf('"', colon + 1);
        int valueEnd = valueStart + 1;
        boolean escaped = false;
        while (valueEnd < json.length()) {
            char current = json.charAt(valueEnd);
            if (current == '"' && !escaped) {
                break;
            }
            escaped = current == '\\' && !escaped;
            if (current != '\\') {
                escaped = false;
            }
            valueEnd++;
        }
        if (colon < 0 || valueStart < 0 || valueEnd >= json.length()) {
            return "";
        }
        return json.substring(valueStart + 1, valueEnd).replace("\\\"", "\"").replace("\\\\", "\\");
    }

    private void addLog(String message) {
        logs.add("[" + LocalDateTime.now().format(TIME_FORMAT) + "] " + message);
    }

    private void sendJson(HttpExchange exchange, int status, String body) throws IOException {
        sendText(exchange, status, body, "application/json");
    }

    private void sendText(HttpExchange exchange, int status, String body, String contentType) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        Headers headers = exchange.getResponseHeaders();
        headers.set("Content-Type", contentType + "; charset=utf-8");
        headers.set("Cache-Control", "no-store");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream response = exchange.getResponseBody()) {
            response.write(bytes);
        }
    }

    private String contentType(Path file) {
        String name = file.getFileName().toString().toLowerCase();
        if (name.endsWith(".css")) {
            return "text/css";
        }
        if (name.endsWith(".js")) {
            return "application/javascript";
        }
        return "text/html";
    }

    private String clean(String value) {
        return value == null ? "" : value.trim();
    }

    private String displayOrPending(String value) {
        return value == null || value.isBlank() ? "pending" : value;
    }

    private String shortHash(String hash) {
        return hash.length() <= 18 ? hash : hash.substring(0, 18) + "...";
    }

    private String nowForData() {
        return LocalDateTime.now().format(DATA_TIME_FORMAT);
    }

    private String randomToken(int bytes) {
        byte[] token = new byte[bytes];
        RANDOM.nextBytes(token);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(token);
    }

    private String escapeJson(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static class StaffUser {
        private String username;
        private String fullName;
        private String role;
        private String salt;
        private String passwordHash;
        private String credentialID;
        private String publicKey;
        private String createdAt;
        private String lastLogin;

        private static StaffUser create(String username, String fullName, String role, String password) throws GeneralSecurityException {
            StaffUser user = new StaffUser();
            user.username = username;
            user.fullName = fullName;
            user.role = role;
            user.salt = newSalt();
            user.passwordHash = hashPassword(password, user.salt);
            user.credentialID = "";
            user.publicKey = "";
            user.createdAt = LocalDateTime.now().format(DATA_TIME_FORMAT);
            user.lastLogin = "";
            return user;
        }

        private boolean matchesPassword(String password) throws GeneralSecurityException {
            return passwordHash.equals(hashPassword(password, salt));
        }

        private String toCsv() {
            return String.join(",",
                    encode(username),
                    encode(fullName),
                    encode(role),
                    encode(salt),
                    encode(passwordHash),
                    encode(credentialID),
                    encode(publicKey),
                    encode(createdAt),
                    encode(lastLogin));
        }

        private static StaffUser fromCsv(String row) {
            String[] columns = row.split(",", -1);
            StaffUser user = new StaffUser();
            user.username = decode(columns, 0);
            user.fullName = decode(columns, 1);
            user.role = decode(columns, 2);
            user.salt = decode(columns, 3);
            user.passwordHash = decode(columns, 4);
            user.credentialID = decode(columns, 5);
            user.publicKey = decode(columns, 6);
            user.createdAt = decode(columns, 7);
            user.lastLogin = decode(columns, 8);
            return user;
        }

        private static String newSalt() {
            byte[] salt = new byte[16];
            RANDOM.nextBytes(salt);
            return Base64.getEncoder().encodeToString(salt);
        }

        private static String hashPassword(String password, String salt) throws GeneralSecurityException {
            byte[] saltBytes = Base64.getDecoder().decode(salt);
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), saltBytes, 120000, 256);
            byte[] hash = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
            return Base64.getEncoder().encodeToString(hash);
        }

        private static String encode(String value) {
            return Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes(StandardCharsets.UTF_8));
        }

        private static String decode(String[] columns, int index) {
            if (index >= columns.length || columns[index].isBlank()) {
                return "";
            }
            return new String(Base64.getUrlDecoder().decode(columns[index]), StandardCharsets.UTF_8);
        }
    }
}
