public class VerifyAddress {

    public static boolean isValidAddress(String address) {
        String[] parts = address.split(":");
        if (parts.length != 2) {
            return false;
        }
        if (!isValidIP(parts[0])) {
            return false;
        }
        return isValidPort(parts[1]);
    }

    public static boolean isValidIP(String ip) {
        if ("localhost".equals(ip)) {
            return true;
        }
        return ip.matches("^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$");
    }

    public static boolean isValidPort(String portStr) {
        try {
            int port = Integer.parseInt(portStr);
            return port > 1024 && port < 65535;
        } catch (NumberFormatException e) {
            return false;
        }
    }
}
