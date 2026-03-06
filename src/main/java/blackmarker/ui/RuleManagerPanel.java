package blackmarker.ui;

import blackmarker.engine.MaskingEngine;
import blackmarker.model.MaskingRule;
import blackmarker.model.RuleCategory;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableColumn;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Panel for managing masking rules: view, add, edit, delete, filter by category.
 * Includes category filter checkboxes and a comprehensive rule editor dialog.
 */
public class RuleManagerPanel extends JPanel {

    private final MaskingEngine engine;
    private final RuleTableModel tableModel;
    private final JTable ruleTable;
    private final JLabel statusLabel;
    private JComboBox<String> categoryFilter;

    public RuleManagerPanel(MaskingEngine engine) {
        this.engine = engine;
        this.tableModel = new RuleTableModel(engine.getRules());

        setLayout(new BorderLayout(5, 5));
        setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        // --- Top: Category filter + search ---
        add(createFilterPanel(), BorderLayout.NORTH);

        // --- Center: Rules table ---
        ruleTable = createRuleTable();
        JScrollPane scrollPane = new JScrollPane(ruleTable);
        scrollPane.setPreferredSize(new Dimension(900, 350));
        add(scrollPane, BorderLayout.CENTER);

        // --- Bottom: Actions + Status ---
        JPanel bottomPanel = new JPanel(new BorderLayout());
        bottomPanel.add(createActionPanel(), BorderLayout.NORTH);
        statusLabel = new JLabel();
        updateStatus();
        bottomPanel.add(statusLabel, BorderLayout.SOUTH);
        add(bottomPanel, BorderLayout.SOUTH);
    }

    private JPanel createFilterPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        panel.setBorder(BorderFactory.createTitledBorder("Filter by Category"));

        categoryFilter = new JComboBox<>();
        categoryFilter.addItem("All Categories");
        for (RuleCategory cat : RuleCategory.values()) {
            categoryFilter.addItem(cat.getDisplayName());
        }
        categoryFilter.addActionListener(e -> applyFilter());
        panel.add(new JLabel("Category:"));
        panel.add(categoryFilter);

        panel.add(Box.createHorizontalStrut(20));

        // Quick enable/disable by category
        JButton enableAll = new JButton("Enable All");
        enableAll.addActionListener(e -> {
            tableModel.setAllEnabled(true);
            updateStatus();
        });
        panel.add(enableAll);

        JButton disableAll = new JButton("Disable All");
        disableAll.addActionListener(e -> {
            tableModel.setAllEnabled(false);
            updateStatus();
        });
        panel.add(disableAll);

        return panel;
    }

    @SuppressWarnings("unchecked")
    private JTable createRuleTable() {
        JTable table = new JTable(tableModel);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setRowHeight(24);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);

        // Column widths
        TableColumn enabledCol = table.getColumnModel().getColumn(0);
        enabledCol.setMaxWidth(60);
        enabledCol.setMinWidth(60);

        TableColumn nameCol = table.getColumnModel().getColumn(1);
        nameCol.setPreferredWidth(180);

        TableColumn categoryCol = table.getColumnModel().getColumn(2);
        categoryCol.setPreferredWidth(140);
        categoryCol.setCellRenderer(new CategoryCellRenderer());

        TableColumn patternCol = table.getColumnModel().getColumn(3);
        patternCol.setPreferredWidth(300);

        TableColumn maskCol = table.getColumnModel().getColumn(4);
        maskCol.setMaxWidth(50);
        maskCol.setMinWidth(50);

        TableColumn builtInCol = table.getColumnModel().getColumn(5);
        builtInCol.setMaxWidth(65);
        builtInCol.setMinWidth(65);

        TableColumn descCol = table.getColumnModel().getColumn(6);
        descCol.setPreferredWidth(250);

        // Row sorter for filtering
        TableRowSorter<RuleTableModel> sorter = new TableRowSorter<>(tableModel);
        table.setRowSorter(sorter);

        // Double-click to edit
        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    editSelectedRule();
                }
            }
        });

        return table;
    }

    private JPanel createActionPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 5));

        JButton addBtn = new JButton("Add Rule");
        addBtn.addActionListener(e -> addNewRule());
        panel.add(addBtn);

        JButton editBtn = new JButton("Edit Rule");
        editBtn.addActionListener(e -> editSelectedRule());
        panel.add(editBtn);

        JButton deleteBtn = new JButton("Delete Rule");
        deleteBtn.addActionListener(e -> deleteSelectedRule());
        panel.add(deleteBtn);

        panel.add(Box.createHorizontalStrut(15));

        JButton duplicateBtn = new JButton("Duplicate");
        duplicateBtn.addActionListener(e -> duplicateSelectedRule());
        panel.add(duplicateBtn);

        panel.add(Box.createHorizontalStrut(15));

        JButton resetBtn = new JButton("Reset to Defaults");
        resetBtn.addActionListener(e -> resetRules());
        panel.add(resetBtn);

        panel.add(Box.createHorizontalStrut(15));

        JButton importBtn = new JButton("Import Rules...");
        importBtn.addActionListener(e -> importRules());
        panel.add(importBtn);

        JButton exportBtn = new JButton("Export Rules...");
        exportBtn.addActionListener(e -> exportRules());
        panel.add(exportBtn);

        return panel;
    }

    @SuppressWarnings("unchecked")
    private void applyFilter() {
        TableRowSorter<RuleTableModel> sorter =
            (TableRowSorter<RuleTableModel>) ruleTable.getRowSorter();

        int selectedIndex = categoryFilter.getSelectedIndex();
        if (selectedIndex <= 0) {
            sorter.setRowFilter(null);
        } else {
            RuleCategory selected = RuleCategory.values()[selectedIndex - 1];
            sorter.setRowFilter(new RowFilter<RuleTableModel, Integer>() {
                @Override
                public boolean include(Entry<? extends RuleTableModel, ? extends Integer> entry) {
                    MaskingRule rule = tableModel.getRuleAt(entry.getIdentifier());
                    return rule != null && rule.getCategory() == selected;
                }
            });
        }
    }

    private void addNewRule() {
        MaskingRule newRule = showRuleDialog(null, "Add New Rule");
        if (newRule != null) {
            engine.addRule(newRule);
            tableModel.refresh();
            updateStatus();
        }
    }

    private void editSelectedRule() {
        int viewRow = ruleTable.getSelectedRow();
        if (viewRow < 0) {
            JOptionPane.showMessageDialog(this, "Please select a rule to edit.",
                "No Selection", JOptionPane.WARNING_MESSAGE);
            return;
        }
        int modelRow = ruleTable.convertRowIndexToModel(viewRow);
        MaskingRule rule = tableModel.getRuleAt(modelRow);
        if (rule == null) return;

        MaskingRule edited = showRuleDialog(rule, "Edit Rule");
        if (edited != null) {
            engine.updateRule(modelRow, edited);
            tableModel.refresh();
            updateStatus();
        }
    }

    private void deleteSelectedRule() {
        int viewRow = ruleTable.getSelectedRow();
        if (viewRow < 0) {
            JOptionPane.showMessageDialog(this, "Please select a rule to delete.",
                "No Selection", JOptionPane.WARNING_MESSAGE);
            return;
        }
        int modelRow = ruleTable.convertRowIndexToModel(viewRow);
        MaskingRule rule = tableModel.getRuleAt(modelRow);
        if (rule == null) return;

        if (rule.isBuiltIn()) {
            int confirm = JOptionPane.showConfirmDialog(this,
                "This is a built-in rule. Disable it instead of deleting?\n" +
                "Click 'Yes' to disable, 'No' to delete permanently.",
                "Built-in Rule", JOptionPane.YES_NO_CANCEL_OPTION);
            if (confirm == JOptionPane.YES_OPTION) {
                rule.setEnabled(false);
                tableModel.refresh();
                updateStatus();
                return;
            } else if (confirm != JOptionPane.NO_OPTION) {
                return;
            }
        }

        engine.removeRule(modelRow);
        tableModel.refresh();
        updateStatus();
    }

    private void duplicateSelectedRule() {
        int viewRow = ruleTable.getSelectedRow();
        if (viewRow < 0) return;
        int modelRow = ruleTable.convertRowIndexToModel(viewRow);
        MaskingRule rule = tableModel.getRuleAt(modelRow);
        if (rule == null) return;

        MaskingRule copy = new MaskingRule(rule);
        copy.setName(rule.getName() + " (Copy)");
        copy.setBuiltIn(false);
        engine.addRule(copy);
        tableModel.refresh();
        updateStatus();
    }

    private void resetRules() {
        int confirm = JOptionPane.showConfirmDialog(this,
            "Reset all rules to defaults? Custom rules will be lost.",
            "Reset Rules", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        if (confirm == JOptionPane.YES_OPTION) {
            engine.resetToDefaults();
            tableModel.refresh();
            updateStatus();
        }
    }

    private void importRules() {
        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle("Import Rules (JSON)");
        if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            try {
                String json = new String(java.nio.file.Files.readAllBytes(
                    fc.getSelectedFile().toPath()));
                engine.loadCustomRules(json);
                tableModel.refresh();
                updateStatus();
                JOptionPane.showMessageDialog(this, "Rules imported successfully.",
                    "Import", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this,
                    "Failed to import rules: " + ex.getMessage(),
                    "Import Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void exportRules() {
        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle("Export Custom Rules (JSON)");
        fc.setSelectedFile(new java.io.File("blackmarker_rules.json"));
        if (fc.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            try {
                String json = engine.serializeCustomRules();
                java.nio.file.Files.write(fc.getSelectedFile().toPath(),
                    json.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                JOptionPane.showMessageDialog(this, "Rules exported successfully.",
                    "Export", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this,
                    "Failed to export rules: " + ex.getMessage(),
                    "Export Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    /**
     * Show a dialog for adding/editing a masking rule.
     * @param existingRule Rule to edit, or null for new rule
     * @param title Dialog title
     * @return The new/edited rule, or null if cancelled
     */
    private MaskingRule showRuleDialog(MaskingRule existingRule, String title) {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 4, 4, 4);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // Name
        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0;
        panel.add(new JLabel("Name:"), gbc);
        JTextField nameField = new JTextField(25);
        gbc.gridx = 1; gbc.weightx = 1;
        panel.add(nameField, gbc);

        // Category
        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0;
        panel.add(new JLabel("Category:"), gbc);
        JComboBox<RuleCategory> categoryBox = new JComboBox<>(RuleCategory.values());
        gbc.gridx = 1; gbc.weightx = 1;
        panel.add(categoryBox, gbc);

        // Regex
        gbc.gridx = 0; gbc.gridy = 2; gbc.weightx = 0;
        panel.add(new JLabel("Regex Pattern:"), gbc);
        JTextField regexField = new JTextField(40);
        regexField.setFont(new Font("Monospaced", Font.PLAIN, 12));
        gbc.gridx = 1; gbc.weightx = 1;
        panel.add(regexField, gbc);

        // Regex validation label
        JLabel regexStatus = new JLabel(" ");
        regexStatus.setFont(new Font("SansSerif", Font.ITALIC, 10));
        gbc.gridx = 1; gbc.gridy = 3;
        panel.add(regexStatus, gbc);

        // Live regex validation
        regexField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            private void validate() {
                try {
                    Pattern.compile(regexField.getText(), Pattern.CASE_INSENSITIVE);
                    regexStatus.setText("Valid regex");
                    regexStatus.setForeground(new Color(44, 160, 44));
                } catch (PatternSyntaxException e) {
                    regexStatus.setText("Invalid: " + e.getDescription());
                    regexStatus.setForeground(Color.RED);
                }
            }
            public void insertUpdate(javax.swing.event.DocumentEvent e) { validate(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { validate(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { validate(); }
        });

        // Mask character
        gbc.gridx = 0; gbc.gridy = 4; gbc.weightx = 0;
        panel.add(new JLabel("Mask Char:"), gbc);
        JTextField maskField = new JTextField(3);
        maskField.setFont(new Font("Monospaced", Font.BOLD, 14));
        gbc.gridx = 1; gbc.weightx = 1;
        panel.add(maskField, gbc);

        // Description
        gbc.gridx = 0; gbc.gridy = 5; gbc.weightx = 0;
        panel.add(new JLabel("Description:"), gbc);
        JTextField descField = new JTextField(40);
        gbc.gridx = 1; gbc.weightx = 1;
        panel.add(descField, gbc);

        // Test area
        gbc.gridx = 0; gbc.gridy = 6; gbc.weightx = 0;
        panel.add(new JLabel("Test Input:"), gbc);
        JTextArea testInput = new JTextArea(3, 40);
        testInput.setFont(new Font("Monospaced", Font.PLAIN, 12));
        gbc.gridx = 1; gbc.weightx = 1;
        panel.add(new JScrollPane(testInput), gbc);

        JButton testBtn = new JButton("Test Regex");
        JLabel testResult = new JLabel(" ");
        gbc.gridx = 0; gbc.gridy = 7;
        panel.add(testBtn, gbc);
        gbc.gridx = 1;
        panel.add(testResult, gbc);

        testBtn.addActionListener(e -> {
            try {
                Pattern p = Pattern.compile(regexField.getText(), Pattern.CASE_INSENSITIVE);
                java.util.regex.Matcher m = p.matcher(testInput.getText());
                int count = 0;
                StringBuilder matches = new StringBuilder();
                while (m.find()) {
                    count++;
                    if (matches.length() > 0) matches.append(", ");
                    String match = m.group();
                    if (match.length() > 30) match = match.substring(0, 30) + "...";
                    matches.append("\"").append(match).append("\"");
                }
                testResult.setText(count + " match(es): " + matches);
                testResult.setForeground(count > 0 ? new Color(44, 160, 44) : Color.ORANGE);
            } catch (PatternSyntaxException ex) {
                testResult.setText("Regex error: " + ex.getDescription());
                testResult.setForeground(Color.RED);
            }
        });

        // Pre-fill if editing
        if (existingRule != null) {
            nameField.setText(existingRule.getName());
            categoryBox.setSelectedItem(existingRule.getCategory());
            regexField.setText(existingRule.getRegex());
            maskField.setText(String.valueOf(existingRule.getMaskChar()));
            descField.setText(existingRule.getDescription());
        } else {
            maskField.setText("\u2588");
            categoryBox.setSelectedItem(RuleCategory.CUSTOM);
        }

        int result = JOptionPane.showConfirmDialog(this, panel, title,
            JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);

        if (result == JOptionPane.OK_OPTION) {
            String name = nameField.getText().trim();
            String regex = regexField.getText().trim();
            if (name.isEmpty() || regex.isEmpty()) {
                JOptionPane.showMessageDialog(this, "Name and regex pattern are required.",
                    "Validation Error", JOptionPane.ERROR_MESSAGE);
                return null;
            }

            // Validate regex
            try {
                Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
            } catch (PatternSyntaxException e) {
                JOptionPane.showMessageDialog(this, "Invalid regex: " + e.getDescription(),
                    "Validation Error", JOptionPane.ERROR_MESSAGE);
                return null;
            }

            char maskChar = maskField.getText().isEmpty() ? '\u2588' : maskField.getText().charAt(0);
            RuleCategory category = (RuleCategory) categoryBox.getSelectedItem();

            return new MaskingRule(name, regex, category, maskChar,
                existingRule != null ? existingRule.isEnabled() : true,
                false, descField.getText().trim());
        }

        return null;
    }

    private void updateStatus() {
        statusLabel.setText(String.format(
            " Rules: %d total, %d enabled | Categories: %d active",
            tableModel.getTotalCount(), tableModel.getEnabledCount(),
            engine.getEnabledCategories().size()
        ));
    }

    /**
     * Refresh the table data.
     */
    public void refresh() {
        tableModel.refresh();
        updateStatus();
    }

    // --- Custom cell renderer for category column ---

    private static class CategoryCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                boolean isSelected, boolean hasFocus, int row, int column) {
            super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            if (value instanceof RuleCategory) {
                RuleCategory cat = (RuleCategory) value;
                setText(cat.getDisplayName());
                if (!isSelected) {
                    setForeground(cat.getColor());
                }
            }
            return this;
        }
    }
}
