import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class mySNS {

    public static void main(String[] args) {

        if (args.length < 6) {
            System.err.println("Insufficient arguments.");
            System.err.println("Usage:");
            System.err.println(
                    "-a <serverAddress> -m <username do médico> -p <password> -u <username do utente> {-sc || -sa || -se || -g} {<filenames>}+ || -au <username> <password> <ficheiro com certificado>");
            System.exit(-1);
        }

        if (!"-a".equals(args[0])) {
            System.err.println("First argument must be -a for server address.");
            System.exit(-1);
        }

        String serverAddress = args[1];

        if (!VerifyAddress.isValidAddress(serverAddress)) {
            System.err.println("Server address must include a valid IP and port (e.g., 127.0.0.1:23456).");
            System.exit(-1);
        }

        String[] addressParts = serverAddress.split(":");
        String ip = addressParts[0];
        int port = Integer.parseInt(addressParts[1]);

        String medico = null;
        String utente = null;
        String username = null;
        String password = null;
        String certificado = null;
        List<String> ficheiros = new ArrayList<>();
        String comando = null;

        // Parse arguments
        for (int i = 2; i < args.length; i++) {
            switch (args[i]) {
                case "-m":
                    medico = args[++i];
                    break;
                case "-p":
                    password = args[++i];
                    break;
                case "-u":
                    utente = args[++i];
                    break;
                case "-sc":
                case "-sa":
                case "-se":
                case "-g":
                    comando = args[i];
                    ficheiros = Arrays.asList(args).subList(i + 1, args.length);
                    i = args.length;
                    break;
                case "-au":
                    comando = args[i];
                    username = args[++i];
                    password = args[++i];
                    certificado = args[++i];
                    i = args.length;
                    break;
            }
        }

        // Validate arguments
        if (comando == null || password == null
                || ("-g".equals(comando) && medico != null)
                || (!"-g".equals(comando) && !"-au".equals(comando) && medico == null)
                || ("-au".equals(comando) && (medico != null || certificado == null))) {
            System.err.println("Incorrect arguments for the specified command.");
            System.exit(-1);
        }

        startClient(ip, port, medico, utente, comando, username, password, certificado, ficheiros);
    }

    private static void startClient(String ip, int port, String medico, String utente, String comando,
            String username, String password, String certificado, List<String> ficheiros) {

        System.out.println("Starting mySNS client...");
        System.out.println("Address verified: " + ip + ":" + port);

        System.out.println("Files to process: " + ficheiros);

        switch (comando) {
            case "-sc":
                System.out.println("Sending files using -sc command...");
                new ComandoSC(ip, port, medico, utente, password, ficheiros).sendToServer();
                break;

            case "-sa":
                new ComandoSA(ip, port, medico, utente, password, ficheiros).execute();
                break;

            case "-se":
                System.out.println("Sending files using -se command...");
                new ComandoSE(ip, port, medico, utente, password, ficheiros).sendToServer();
                break;

            case "-g":
                System.out.println("Processing files using -g command...");
                new ComandoG(ip, port, utente, ficheiros).sendToServer();
                break;

            case "-au":
                System.out.println("A processar novo utilizador...");
                new ComandoAU(ip, port, username, password, certificado).sendToServer();
                ;
                break;

            default:
                System.err.println("Unsupported command: " + comando);
                break;
        }
    }
}
