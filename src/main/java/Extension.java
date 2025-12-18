import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.List;

/**
 * Burp Suite Extension that automatically fixes HMAC SHA256 signatures on HTTP requests.
 * 
 * This extension intercepts all outgoing HTTP requests and calculates an HMAC SHA256
 * signature based on the request parameters, then adds it as a 'signature' parameter.
 * 
 * Useful for testing APIs that require HMAC authentication (e.g., Shopify-style webhooks).
 * 
 * @author Your Name
 * @version 1.0.0
 */
public class Extension implements BurpExtension, HttpHandler {
    
    private MontoyaApi api;
    private JTextField secretField;
    private JCheckBox enabledCheckbox;
    private String sharedSecret = "";
    private boolean enabled = true;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("HMAC Signature Fixer");
        
        // Register HTTP handler to intercept all requests
        api.http().registerHttpHandler(this);
        
        // Create configuration UI
        createConfigUI();
        
        api.logging().logToOutput("✓ HMAC Signature Fixer loaded successfully!");
        api.logging().logToOutput("✓ Ready to sign requests automatically");
    }

    /**
     * Creates the configuration UI tab in Burp Suite.
     */
    private void createConfigUI() {
        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BorderLayout(10, 10));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));

        // Title
        JLabel titleLabel = new JLabel("HMAC SHA256 Signature Configuration");
        titleLabel.setFont(new Font("Arial", Font.BOLD, 16));
        mainPanel.add(titleLabel, BorderLayout.NORTH);

        // Config panel
        JPanel configPanel = new JPanel();
        configPanel.setLayout(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // Enabled checkbox
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 2;
        enabledCheckbox = new JCheckBox("Enable automatic signature fixing", true);
        enabledCheckbox.addActionListener(e -> {
            enabled = enabledCheckbox.isSelected();
            api.logging().logToOutput("HMAC Fixer " + (enabled ? "ENABLED" : "DISABLED"));
        });
        configPanel.add(enabledCheckbox, gbc);

        // Secret label
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.gridwidth = 1;
        gbc.weightx = 0;
        JLabel secretLabel = new JLabel("Shared Secret:");
        configPanel.add(secretLabel, gbc);

        // Secret field
        gbc.gridx = 1;
        gbc.gridy = 1;
        gbc.weightx = 1.0;
        secretField = new JTextField(30);
        secretField.setToolTipText("Enter the shared secret for HMAC signature");
        configPanel.add(secretField, gbc);

        // Save button
        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.gridwidth = 2;
        gbc.weightx = 0;
        JButton saveButton = new JButton("💾 Save Secret");
        saveButton.addActionListener(e -> {
            sharedSecret = secretField.getText().trim();
            if (!sharedSecret.isEmpty()) {
                JOptionPane.showMessageDialog(mainPanel, 
                    "Secret saved successfully!\nLength: " + sharedSecret.length() + " characters", 
                    "✓ Success", 
                    JOptionPane.INFORMATION_MESSAGE);
                api.logging().logToOutput("Secret updated (length: " + sharedSecret.length() + ")");
            } else {
                JOptionPane.showMessageDialog(mainPanel,
                    "Please enter a valid secret!",
                    "⚠ Warning",
                    JOptionPane.WARNING_MESSAGE);
            }
        });
        configPanel.add(saveButton, gbc);

        // Clear button
        gbc.gridx = 0;
        gbc.gridy = 3;
        gbc.gridwidth = 2;
        JButton clearButton = new JButton("🗑 Clear Secret");
        clearButton.addActionListener(e -> {
            secretField.setText("");
            sharedSecret = "";
            api.logging().logToOutput("Secret cleared");
        });
        configPanel.add(clearButton, gbc);

        // Info panel
        JPanel infoPanel = new JPanel(new BorderLayout());
        infoPanel.setBorder(BorderFactory.createTitledBorder("ℹ️ How it works"));
        JTextArea infoText = new JTextArea(
            "This extension automatically adds HMAC SHA256 signatures\n" +
            "to HTTP request parameters.\n\n" +
            "✓ Works in: Repeater, Intruder, Scanner, and Proxy\n" +
            "✓ Removes existing 'signature' parameter (if present)\n" +
            "✓ Calculates new signature from alphabetically sorted parameters\n" +
            "✓ Adds 'signature' parameter to query string\n\n" +
            "Algorithm: HMAC-SHA256(sorted_params) → hex lowercase\n" +
            "Format: key1=value1key2=value2... (no separators)"
        );
        infoText.setEditable(false);
        infoText.setBackground(mainPanel.getBackground());
        infoText.setFont(new Font("Monospaced", Font.PLAIN, 11));
        infoPanel.add(new JScrollPane(infoText), BorderLayout.CENTER);

        mainPanel.add(configPanel, BorderLayout.CENTER);
        mainPanel.add(infoPanel, BorderLayout.SOUTH);

        // Register UI tab
        api.userInterface().registerSuiteTab("HMAC Fixer", mainPanel);
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent req) {
        // If disabled or secret is empty, pass through without modifications
        if (!enabled || sharedSecret.isEmpty()) {
            return RequestToBeSentAction.continueWith(req);
        }

        try {
            HttpRequest signedRequest = addSignature(req);
            return RequestToBeSentAction.continueWith(signedRequest);
        } catch (Exception e) {
            api.logging().logToError("❌ Error signing request: " + e.getMessage());
            e.printStackTrace();
            return RequestToBeSentAction.continueWith(req);
        }
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived resp) {
        // We don't modify responses
        return ResponseReceivedAction.continueWith(resp);
    }

    /**
     * Adds HMAC SHA256 signature to the HTTP request.
     * 
     * @param req The original HTTP request
     * @return Modified HTTP request with signature parameter
     * @throws Exception If signature calculation fails
     */
    private HttpRequest addSignature(HttpRequest req) throws Exception {
        List<ParsedHttpParameter> params = req.parameters();
        
        // Collect parameters (exclude existing signature)
        Map<String, List<String>> collected = new TreeMap<>(); // TreeMap for automatic sorting
        List<ParsedHttpParameter> toRemove = new ArrayList<>();

        for (ParsedHttpParameter p : params) {
            // Remove old signature if present
            if (p.name().equals("signature")) {
                toRemove.add(p);
                continue;
            }

            // Collect only URL and BODY parameters
            if (p.type() == HttpParameterType.URL || p.type() == HttpParameterType.BODY) {
                // IMPORTANT: URL-decode the value before adding to signature calculation
                // Shopify docs: "The signature is unencoded, sorted, concatenated..."
                String decodedValue = urlDecode(p.value());
                collected
                    .computeIfAbsent(p.name(), k -> new ArrayList<>())
                    .add(decodedValue);
            }
        }

        // Build sorted string: key1=value1key2=value2...
        StringBuilder sortedParams = new StringBuilder();
        for (Map.Entry<String, List<String>> e : collected.entrySet()) {
            sortedParams.append(e.getKey())
                       .append("=")
                       .append(String.join(",", e.getValue()));
        }

        String dataToSign = sortedParams.toString();
        
        // Calculate HMAC SHA256
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec key = new SecretKeySpec(
            sharedSecret.getBytes(StandardCharsets.UTF_8),
            "HmacSHA256"
        );
        mac.init(key);

        byte[] raw = mac.doFinal(dataToSign.getBytes(StandardCharsets.UTF_8));
        String signature = bytesToHex(raw);

        // Debug log
        api.logging().logToOutput("🔐 Signed: " + dataToSign + " → " + signature.substring(0, 16) + "...");

        // Build new request: remove old signature and add new one
        HttpRequest modifiedReq = req.withRemovedParameters(toRemove);
        
        HttpParameter sigParam = HttpParameter.parameter(
            "signature",
            signature,
            HttpParameterType.URL
        );

        modifiedReq = modifiedReq.withAddedParameters(List.of(sigParam));

        return modifiedReq;
    }

    /**
     * Converts byte array to hexadecimal string.
     * 
     * @param bytes Byte array to convert
     * @return Hexadecimal string (lowercase)
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * URL-decodes a string value.
     * Shopify requires unencoded values for signature calculation.
     * 
     * @param value The URL-encoded string
     * @return Decoded string
     */
    private static String urlDecode(String value) {
        try {
            return java.net.URLDecoder.decode(value, StandardCharsets.UTF_8);
        } catch (Exception e) {
            // If decode fails, return original value
            return value;
        }
    }
}