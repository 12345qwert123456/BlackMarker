package blackmarker.ui;

import blackmarker.engine.MaskingEngine;
import blackmarker.export.SessionExporter;
import blackmarker.model.CustomCategory;
import blackmarker.model.PluginSettings;
import blackmarker.model.RuleCategory;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.util.EnumMap;
import java.util.Map;

/**
 * Main BlackMarker tab registered in Burp Suite's top-level tab bar.
 * Contains: master toggle, category toggles, rule manager, smart detection settings,
 * session auto-learn controls, and a live test area.
 */
public class BlackMarkerTab extends JPanel {

    private final MaskingEngine engine;
    private final RuleManagerPanel ruleManagerPanel;
    private JToggleButton masterToggle;
    private final Map<RuleCategory, JCheckBox> categoryCheckboxes;
    private JLabel trackedValuesLabel;
    private MaskedTextPane testOutputPane;
    private SessionExporter exporter;

    public BlackMarkerTab(MaskingEngine engine) {
        this.engine = engine;
        this.categoryCheckboxes = new EnumMap<>(RuleCategory.class);

        setLayout(new BorderLayout(5, 5));
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        // ===== TOP: Header + Master Toggle =====
        JPanel headerPanel = createHeaderPanel();
        add(headerPanel, BorderLayout.NORTH);

        // ===== CENTER: Tabbed pane with Rules, Settings, Test =====
        JTabbedPane tabbedPane = new JTabbedPane();

        // Tab 1: Rule Manager
        ruleManagerPanel = new RuleManagerPanel(engine);
        tabbedPane.addTab("Rules", ruleManagerPanel);

        // Tab 2: Settings
        tabbedPane.addTab("Settings", createSettingsPanel());

        // Tab 3: Live Test
        tabbedPane.addTab("Live Test", createTestPanel());

        // Tab 4: Auto-Learn
        tabbedPane.addTab("Auto-Learn", createAutoLearnPanel());

        add(tabbedPane, BorderLayout.CENTER);

        // ===== BOTTOM: Status bar =====
        JPanel statusBar = createStatusBar();
        add(statusBar, BorderLayout.SOUTH);

        updateTrackedLabel();
    }

    private JPanel createHeaderPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(0, 0, 5, 0));

        JPanel leftPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));

        // Logo / Title
        JLabel titleLabel = new JLabel("\u2588 BlackMarker");
        titleLabel.setFont(new Font("SansSerif", Font.BOLD, 20));
        titleLabel.setForeground(new Color(65, 105, 225));
        leftPanel.add(titleLabel);

        // Master toggle
        masterToggle = new JToggleButton("MASKING ON", true);
        masterToggle.setFont(new Font("SansSerif", Font.BOLD, 13));
        masterToggle.setForeground(ColorScheme.STATUS_ENABLED);
        masterToggle.setPreferredSize(new Dimension(150, 32));
        masterToggle.addActionListener(e -> {
            boolean on = masterToggle.isSelected();
            engine.setEnabled(on);
            masterToggle.setText(on ? "MASKING ON" : "MASKING OFF");
            masterToggle.setForeground(on ? ColorScheme.STATUS_ENABLED : ColorScheme.STATUS_DISABLED);
        });
        leftPanel.add(masterToggle);

        // Export button
        JButton exportBtn = new JButton("Export Session...");
        exportBtn.addActionListener(e -> {
            if (exporter != null) {
                exporter.showExportDialog(this);
            }
        });
        leftPanel.add(exportBtn);

        panel.add(leftPanel, BorderLayout.WEST);

        // Category quick toggles on the right
        JPanel catPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 5));
        catPanel.add(new JLabel("Categories: "));
        for (RuleCategory cat : RuleCategory.values()) {
            JCheckBox cb = new JCheckBox(cat.getDisplayName(), true);
            cb.setForeground(cat.getColor());
            cb.setFont(new Font("SansSerif", Font.BOLD, 11));
            cb.addActionListener(e -> engine.setCategoryEnabled(cat, cb.isSelected()));
            categoryCheckboxes.put(cat, cb);
            catPanel.add(cb);
        }
        panel.add(catPanel, BorderLayout.EAST);

        return panel;
    }

    private JPanel createSettingsPanel() {
        PluginSettings settings = PluginSettings.getInstance();

        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        GridBagConstraints gc = new GridBagConstraints();
        gc.gridx = 0; gc.fill = GridBagConstraints.HORIZONTAL;
        gc.weightx = 1.0; gc.anchor = GridBagConstraints.NORTHWEST;
        int gcRow = 0;

        // ===================== Appearance =====================
        JPanel appearPanel = new JPanel(new GridBagLayout());
        appearPanel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(), "Appearance",
            TitledBorder.LEFT, TitledBorder.TOP));
        GridBagConstraints g = new GridBagConstraints();
        g.insets = new Insets(4, 8, 4, 8);
        g.anchor = GridBagConstraints.WEST;

        // Monochrome checkbox
        JCheckBox monoCb = new JCheckBox("Monochrome mode (single color for all categories)",
            settings.isMonochrome());
        monoCb.addActionListener(e -> settings.setMonochrome(monoCb.isSelected()));
        g.gridx = 0; g.gridy = 0; g.gridwidth = 3;
        appearPanel.add(monoCb, g);

        // Global mask character
        g.gridwidth = 1;
        g.gridx = 0; g.gridy = 1;
        appearPanel.add(new JLabel("Global mask character:"), g);
        JTextField maskCharField = new JTextField(String.valueOf(settings.getGlobalMaskChar()), 3);
        maskCharField.setFont(new Font("Monospaced", Font.BOLD, 14));
        maskCharField.setHorizontalAlignment(JTextField.CENTER);
        maskCharField.addActionListener(e -> {
            String txt = maskCharField.getText();
            if (!txt.isEmpty()) settings.setGlobalMaskChar(txt.charAt(0));
        });
        // Also update on focus lost
        maskCharField.addFocusListener(new java.awt.event.FocusAdapter() {
            @Override public void focusLost(java.awt.event.FocusEvent e) {
                String txt = maskCharField.getText();
                if (!txt.isEmpty()) settings.setGlobalMaskChar(txt.charAt(0));
            }
        });
        g.gridx = 1;
        appearPanel.add(maskCharField, g);
        JLabel maskHelp = new JLabel("(rules can override per-rule)");
        maskHelp.setFont(new Font("SansSerif", Font.ITALIC, 11));
        maskHelp.setForeground(Color.GRAY);
        g.gridx = 2;
        appearPanel.add(maskHelp, g);

        // Truncation
        g.gridx = 0; g.gridy = 2; g.gridwidth = 1;
        JCheckBox truncCb = new JCheckBox("Truncate long masked strings",
            settings.isTruncationEnabled());
        truncCb.addActionListener(e -> settings.setTruncationEnabled(truncCb.isSelected()));
        appearPanel.add(truncCb, g);

        g.gridx = 1;
        appearPanel.add(new JLabel("Max chars:"), g);

        JSpinner truncSpinner = new JSpinner(new SpinnerNumberModel(
            settings.getMaxMaskedLength(), 4, 200, 1));
        truncSpinner.addChangeListener(e ->
            settings.setMaxMaskedLength((Integer) truncSpinner.getValue()));
        g.gridx = 2;
        appearPanel.add(truncSpinner, g);

        JLabel truncHelp = new JLabel("Long tokens (e.g. JWT) will be shortened: \u2588\u2588\u2588\u2588\u2026\u2588\u2588\u2588\u2588");
        truncHelp.setFont(new Font("SansSerif", Font.ITALIC, 11));
        truncHelp.setForeground(Color.GRAY);
        g.gridx = 0; g.gridy = 3; g.gridwidth = 3;
        appearPanel.add(truncHelp, g);

        gc.gridy = gcRow++; gc.insets = new Insets(0, 0, 4, 0);
        panel.add(appearPanel, gc);

        // ===================== Category Colors =====================
        JPanel catColorsPanel = new JPanel(new BorderLayout(5, 5));
        catColorsPanel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(), "Category Colors",
            TitledBorder.LEFT, TitledBorder.TOP));

        // Built-in categories table
        String[] catCols = {"Category", "Text Color", "Background", ""};
        Object[][] catData = new Object[RuleCategory.values().length][4];
        for (int i = 0; i < RuleCategory.values().length; i++) {
            RuleCategory cat = RuleCategory.values()[i];
            catData[i][0] = cat.getDisplayName();
            catData[i][1] = ColorScheme.getCategoryForegroundColor(cat);
            catData[i][2] = ColorScheme.getCategoryBackgroundColor(cat);
            catData[i][3] = "Edit";
        }

        JTable catTable = new JTable(catData, catCols) {
            @Override public boolean isCellEditable(int row, int col) { return col == 3; }
        };
        catTable.setRowHeight(24);

        // Color cell renderer
        DefaultTableCellRenderer colorRenderer = new DefaultTableCellRenderer() {
            @Override public Component getTableCellRendererComponent(JTable table, Object value,
                    boolean isSelected, boolean hasFocus, int row, int column) {
                JLabel label = (JLabel) super.getTableCellRendererComponent(
                    table, "", isSelected, hasFocus, row, column);
                if (value instanceof Color c) {
                    label.setOpaque(true);
                    label.setBackground(c);
                    label.setText(String.format("#%02x%02x%02x", c.getRed(), c.getGreen(), c.getBlue()));
                    label.setForeground(brightness(c) < 128 ? Color.WHITE : Color.BLACK);
                }
                return label;
            }
        };
        catTable.getColumnModel().getColumn(1).setCellRenderer(colorRenderer);
        catTable.getColumnModel().getColumn(2).setCellRenderer(colorRenderer);
        catTable.getColumnModel().getColumn(3).setMaxWidth(60);

        catTable.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override public void mouseClicked(java.awt.event.MouseEvent e) {
                int row = catTable.rowAtPoint(e.getPoint());
                int col = catTable.columnAtPoint(e.getPoint());
                if (row < 0) return;
                RuleCategory cat = RuleCategory.values()[row];

                if (col == 1) {
                    Color chosen = JColorChooser.showDialog(panel, "Choose Text Color for " + cat.getDisplayName(),
                        (Color) catTable.getValueAt(row, 1));
                    if (chosen != null) {
                        settings.setCategoryFgOverride(cat, chosen);
                        catTable.setValueAt(chosen, row, 1);
                    }
                } else if (col == 2) {
                    Color chosen = JColorChooser.showDialog(panel, "Choose Background for " + cat.getDisplayName(),
                        (Color) catTable.getValueAt(row, 2));
                    if (chosen != null) {
                        settings.setCategoryBgOverride(cat, chosen);
                        catTable.setValueAt(chosen, row, 2);
                    }
                } else if (col == 3) {
                    // Reset to default
                    settings.setCategoryFgOverride(cat, null);
                    settings.setCategoryBgOverride(cat, null);
                    catTable.setValueAt(ColorScheme.getCategoryForegroundColor(cat), row, 1);
                    catTable.setValueAt(ColorScheme.getCategoryBackgroundColor(cat), row, 2);
                }
            }
        });

        JScrollPane catScroll = new JScrollPane(catTable);
        catScroll.setPreferredSize(new Dimension(500, 130));
        catColorsPanel.add(catScroll, BorderLayout.CENTER);

        JLabel catHelp = new JLabel("Click text/background cells to change color. Click \"Edit\" to reset.");
        catHelp.setFont(new Font("SansSerif", Font.ITALIC, 11));
        catHelp.setForeground(Color.GRAY);
        catColorsPanel.add(catHelp, BorderLayout.SOUTH);

        gc.gridy = gcRow++; gc.insets = new Insets(0, 0, 4, 0);
        panel.add(catColorsPanel, gc);

        // ===================== Custom Categories =====================
        JPanel customCatPanel = new JPanel(new BorderLayout(5, 5));
        customCatPanel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(), "Custom Categories",
            TitledBorder.LEFT, TitledBorder.TOP));

        CustomCategoryTableModel ccModel = new CustomCategoryTableModel();
        JTable ccTable = new JTable(ccModel);
        ccTable.setRowHeight(24);
        ccTable.getColumnModel().getColumn(1).setCellRenderer(colorRenderer);
        ccTable.getColumnModel().getColumn(2).setCellRenderer(colorRenderer);

        ccTable.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override public void mouseClicked(java.awt.event.MouseEvent e) {
                int row = ccTable.rowAtPoint(e.getPoint());
                int col = ccTable.columnAtPoint(e.getPoint());
                if (row < 0 || row >= settings.getCustomCategories().size()) return;
                CustomCategory cc = settings.getCustomCategories().get(row);

                if (col == 1) {
                    Color chosen = JColorChooser.showDialog(panel, "Text Color for " + cc.getName(), cc.getForeground());
                    if (chosen != null) { cc.setForeground(chosen); ccModel.fireTableRowsUpdated(row, row); }
                } else if (col == 2) {
                    Color chosen = JColorChooser.showDialog(panel, "Background for " + cc.getName(), cc.getBackground());
                    if (chosen != null) { cc.setBackground(chosen); ccModel.fireTableRowsUpdated(row, row); }
                }
            }
        });

        JScrollPane ccScroll = new JScrollPane(ccTable);
        ccScroll.setPreferredSize(new Dimension(500, 70));
        customCatPanel.add(ccScroll, BorderLayout.CENTER);

        JPanel ccButtons = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        JButton addCcBtn = new JButton("+ Add Category");
        addCcBtn.addActionListener(e -> {
            String name = JOptionPane.showInputDialog(panel, "Category name:", "New Custom Category",
                JOptionPane.PLAIN_MESSAGE);
            if (name != null && !name.trim().isEmpty()) {
                Color fg = JColorChooser.showDialog(panel, "Choose text color", new Color(80, 80, 80));
                if (fg == null) fg = new Color(80, 80, 80);
                Color bg = JColorChooser.showDialog(panel, "Choose background color", new Color(230, 230, 230));
                if (bg == null) bg = new Color(230, 230, 230);
                settings.addCustomCategory(new CustomCategory(name.trim(), fg, bg));
                ccModel.fireTableDataChanged();
            }
        });
        ccButtons.add(addCcBtn);

        JButton editCcBtn = new JButton("Edit Name");
        editCcBtn.addActionListener(e -> {
            int row = ccTable.getSelectedRow();
            if (row >= 0 && row < settings.getCustomCategories().size()) {
                CustomCategory cc = settings.getCustomCategories().get(row);
                String newName = JOptionPane.showInputDialog(panel, "New name:", cc.getName());
                if (newName != null && !newName.trim().isEmpty()) {
                    cc.setName(newName.trim());
                    ccModel.fireTableRowsUpdated(row, row);
                }
            }
        });
        ccButtons.add(editCcBtn);

        JButton removeCcBtn = new JButton("- Remove");
        removeCcBtn.addActionListener(e -> {
            int row = ccTable.getSelectedRow();
            if (row >= 0) {
                settings.removeCustomCategory(row);
                ccModel.fireTableDataChanged();
            }
        });
        ccButtons.add(removeCcBtn);
        customCatPanel.add(ccButtons, BorderLayout.SOUTH);

        gc.gridy = gcRow++; gc.insets = new Insets(0, 0, 4, 0);
        panel.add(customCatPanel, gc);

        // ===================== Entropy Detection =====================
        JPanel entropyPanel = new JPanel(new GridBagLayout());
        entropyPanel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(), "Smart Detection (Entropy-based)",
            TitledBorder.LEFT, TitledBorder.TOP));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 8, 4, 8);
        gbc.anchor = GridBagConstraints.WEST;

        JCheckBox entropyEnabled = new JCheckBox("Enable entropy-based detection",
            engine.getEntropyDetector().isEnabled());
        entropyEnabled.addActionListener(e ->
            engine.getEntropyDetector().setEnabled(entropyEnabled.isSelected()));
        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 2;
        entropyPanel.add(entropyEnabled, gbc);

        gbc.gridwidth = 1;
        gbc.gridx = 0; gbc.gridy = 1;
        entropyPanel.add(new JLabel("Entropy threshold (bits):"), gbc);
        JSpinner thresholdSpinner = new JSpinner(new SpinnerNumberModel(
            engine.getEntropyDetector().getEntropyThreshold(), 1.0, 8.0, 0.1));
        thresholdSpinner.addChangeListener(e ->
            engine.getEntropyDetector().setEntropyThreshold(
                (Double) thresholdSpinner.getValue()));
        gbc.gridx = 1;
        entropyPanel.add(thresholdSpinner, gbc);

        gbc.gridx = 0; gbc.gridy = 2;
        entropyPanel.add(new JLabel("Min string length:"), gbc);
        JSpinner minLenSpinner = new JSpinner(new SpinnerNumberModel(
            engine.getEntropyDetector().getMinLength(), 8, 200, 1));
        minLenSpinner.addChangeListener(e ->
            engine.getEntropyDetector().setMinLength((Integer) minLenSpinner.getValue()));
        gbc.gridx = 1;
        entropyPanel.add(minLenSpinner, gbc);

        gbc.gridx = 0; gbc.gridy = 3;
        entropyPanel.add(new JLabel("Max string length:"), gbc);
        JSpinner maxLenSpinner = new JSpinner(new SpinnerNumberModel(
            engine.getEntropyDetector().getMaxLength(), 50, 10000, 50));
        maxLenSpinner.addChangeListener(e ->
            engine.getEntropyDetector().setMaxLength((Integer) maxLenSpinner.getValue()));
        gbc.gridx = 1;
        entropyPanel.add(maxLenSpinner, gbc);

        JLabel entropyHelp = new JLabel("Recommended threshold: 4.0\u20135.0 (lower = more aggressive)");
        entropyHelp.setFont(new Font("SansSerif", Font.ITALIC, 11));
        entropyHelp.setForeground(Color.GRAY);
        gbc.gridx = 0; gbc.gridy = 4; gbc.gridwidth = 2;
        entropyPanel.add(entropyHelp, gbc);

        gc.gridy = gcRow++; gc.insets = new Insets(0, 0, 0, 0);
        panel.add(entropyPanel, gc);

        // Vertical spacer to push content to top
        gc.gridy = gcRow; gc.weighty = 1.0;
        panel.add(Box.createGlue(), gc);

        // Wrap in scrollpane for small screens
        JScrollPane scroll = new JScrollPane(panel);
        scroll.setBorder(null);
        scroll.getVerticalScrollBar().setUnitIncrement(16);
        JPanel wrapper = new JPanel(new BorderLayout());
        wrapper.add(scroll, BorderLayout.CENTER);
        return wrapper;
    }

    private static int brightness(Color c) {
        return (int) (0.299 * c.getRed() + 0.587 * c.getGreen() + 0.114 * c.getBlue());
    }

    /**
     * Table model for user-defined custom categories.
     */
    private static class CustomCategoryTableModel extends AbstractTableModel {
        private final PluginSettings settings = PluginSettings.getInstance();
        private final String[] columns = {"Name", "Text Color", "Background"};

        @Override public int getRowCount() { return settings.getCustomCategories().size(); }
        @Override public int getColumnCount() { return columns.length; }
        @Override public String getColumnName(int col) { return columns[col]; }

        @Override
        public Object getValueAt(int row, int col) {
            CustomCategory cc = settings.getCustomCategories().get(row);
            return switch (col) {
                case 0 -> cc.getName();
                case 1 -> cc.getForeground();
                case 2 -> cc.getBackground();
                default -> "";
            };
        }

        @Override public boolean isCellEditable(int row, int col) { return false; }
    }

    private JPanel createTestPanel() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Input
        JPanel inputPanel = new JPanel(new BorderLayout(5, 5));
        inputPanel.setBorder(BorderFactory.createTitledBorder("Test Input (paste HTTP traffic)"));
        JTextArea testInput = new JTextArea(10, 80);
        testInput.setFont(new Font("Monospaced", Font.PLAIN, 13));
        testInput.setText(
            "GET /api/users?email=test@example.com&token=ghp_ABCDEFghijklmnop1234567890abcdef12 HTTP/1.1\n" +
            "Host: api.internal.corp\n" +
            "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjg\n" +
            "Cookie: session_id=abc123def456; PHPSESSID=s9df8g7sd6fg5sd4fg\n" +
            "X-API-Key: AIzaSyB-FAKE_GOOGLE_KEY_1234567890abc\n" +
            "\n" +
            "{\n" +
            "  \"password\": \"SuperSecret123!\",\n" +
            "  \"credit_card\": \"4532-0150-1234-5678\",\n" +
            "  \"email\": \"john.doe@company.com\",\n" +
            "  \"ssn\": \"123-45-6789\",\n" +
            "  \"api_key\": \"sk_test_4eC39HqLyjWDarjtT1zdp7dc\",\n" +
            "  \"aws_secret_access_key\": \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\",\n" +
            "  \"ip\": \"192.168.1.100\",\n" +
            "  \"db_url\": \"postgres://admin:password123@db.internal.corp:5432/mydb\"\n" +
            "}"
        );
        inputPanel.add(new JScrollPane(testInput), BorderLayout.CENTER);

        JButton testBtn = new JButton("Run Masking Test");
        testBtn.setFont(new Font("SansSerif", Font.BOLD, 12));
        inputPanel.add(testBtn, BorderLayout.SOUTH);

        panel.add(inputPanel, BorderLayout.NORTH);

        // Output
        JPanel outputPanel = new JPanel(new BorderLayout(5, 5));
        outputPanel.setBorder(BorderFactory.createTitledBorder("Masked Output"));
        testOutputPane = new MaskedTextPane();
        outputPanel.add(new JScrollPane(testOutputPane), BorderLayout.CENTER);

        JLabel outputStatus = new JLabel(" ");
        outputStatus.setFont(new Font("SansSerif", Font.PLAIN, 11));
        outputPanel.add(outputStatus, BorderLayout.SOUTH);

        panel.add(outputPanel, BorderLayout.CENTER);

        // Test button action
        testBtn.addActionListener(e -> {
            String input = testInput.getText();
            var result = engine.mask(input);
            testOutputPane.displayMaskedResult(result);
            outputStatus.setText(result.getSummary());
            outputStatus.setForeground(result.hasMatches() ?
                ColorScheme.WARNING : Color.GRAY);
        });

        return panel;
    }

    private JPanel createAutoLearnPanel() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Controls
        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        controlPanel.setBorder(BorderFactory.createTitledBorder("Session Auto-Learn"));

        JCheckBox autoLearnEnabled = new JCheckBox("Enable auto-learning of session values",
            engine.getSessionValueTracker().isEnabled());
        autoLearnEnabled.addActionListener(e ->
            engine.getSessionValueTracker().setEnabled(autoLearnEnabled.isSelected()));
        controlPanel.add(autoLearnEnabled);

        trackedValuesLabel = new JLabel();
        controlPanel.add(trackedValuesLabel);

        JButton clearBtn = new JButton("Clear Tracked Values");
        clearBtn.addActionListener(e -> {
            engine.getSessionValueTracker().clearTrackedValues();
            updateTrackedLabel();
        });
        controlPanel.add(clearBtn);

        JButton refreshBtn = new JButton("Refresh");
        refreshBtn.addActionListener(e -> updateTrackedLabel());
        controlPanel.add(refreshBtn);

        panel.add(controlPanel, BorderLayout.NORTH);

        // Display tracked values
        JTextArea trackedDisplay = new JTextArea(15, 80);
        trackedDisplay.setEditable(false);
        trackedDisplay.setFont(new Font("Monospaced", Font.PLAIN, 12));

        refreshBtn.addActionListener(e -> {
            StringBuilder sb = new StringBuilder();
            sb.append("Tracked Session Values:\n");
            sb.append("======================\n\n");
            var tracked = engine.getSessionValueTracker().getTrackedValues();
            if (tracked.isEmpty()) {
                sb.append("No values tracked yet. Browse websites through Burp to start auto-learning.\n");
            } else {
                for (var entry : tracked.entrySet()) {
                    String value = entry.getKey();
                    String source = entry.getValue();
                    // Truncate long values for display
                    String displayValue = value.length() > 60
                        ? value.substring(0, 60) + "..."
                        : value;
                    sb.append(String.format("%-20s  %s\n", source, displayValue));
                }
            }
            trackedDisplay.setText(sb.toString());
            updateTrackedLabel();
        });

        panel.add(new JScrollPane(trackedDisplay), BorderLayout.CENTER);

        // Help text
        JLabel helpLabel = new JLabel(
            "Auto-learn tracks session cookies, CSRF tokens, and auth tokens from HTTP traffic.");
        helpLabel.setFont(new Font("SansSerif", Font.ITALIC, 11));
        helpLabel.setForeground(Color.GRAY);
        helpLabel.setBorder(BorderFactory.createEmptyBorder(5, 0, 0, 0));
        panel.add(helpLabel, BorderLayout.SOUTH);

        return panel;
    }

    private JPanel createStatusBar() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 2));
        panel.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, Color.GRAY));

        JLabel versionLabel = new JLabel("BlackMarker v1.0.0");
        versionLabel.setFont(new Font("SansSerif", Font.PLAIN, 11));
        versionLabel.setForeground(Color.GRAY);
        panel.add(versionLabel);

        panel.add(new JSeparator(SwingConstants.VERTICAL));

        JPanel legendSmall = ColorScheme.createLegendPanel();
        panel.add(legendSmall);

        return panel;
    }

    private void updateTrackedLabel() {
        int count = engine.getSessionValueTracker().getTrackedValueCount();
        if (trackedValuesLabel != null) {
            trackedValuesLabel.setText("Tracked values: " + count);
            trackedValuesLabel.setForeground(count > 0 ? ColorScheme.SUCCESS : Color.GRAY);
        }
    }

    /**
     * Get the current master toggle button (used by BlackMarkerExtension for setup).
     */
    public JToggleButton getMasterToggle() {
        return masterToggle;
    }

    /**
     * Set the session exporter (called from BlackMarkerExtension after initialization).
     */
    public void setExporter(SessionExporter exporter) {
        this.exporter = exporter;
    }

    /**
     * Refresh all UI components.
     */
    public void refresh() {
        ruleManagerPanel.refresh();
        updateTrackedLabel();
    }
}
