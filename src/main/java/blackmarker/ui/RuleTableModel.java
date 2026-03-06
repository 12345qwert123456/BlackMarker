package blackmarker.ui;

import blackmarker.model.MaskingRule;
import blackmarker.model.RuleCategory;

import javax.swing.table.AbstractTableModel;
import java.util.List;

/**
 * Table model for displaying and editing masking rules in the Rule Manager panel.
 */
public class RuleTableModel extends AbstractTableModel {

    private static final String[] COLUMN_NAMES = {
        "Enabled", "Name", "Category", "Pattern (Regex)", "Mask", "Built-in", "Description"
    };

    private static final Class<?>[] COLUMN_TYPES = {
        Boolean.class, String.class, RuleCategory.class, String.class,
        String.class, Boolean.class, String.class
    };

    private final List<MaskingRule> rules;

    public RuleTableModel(List<MaskingRule> rules) {
        this.rules = rules;
    }

    @Override
    public int getRowCount() {
        return rules.size();
    }

    @Override
    public int getColumnCount() {
        return COLUMN_NAMES.length;
    }

    @Override
    public String getColumnName(int column) {
        return COLUMN_NAMES[column];
    }

    @Override
    public Class<?> getColumnClass(int column) {
        return COLUMN_TYPES[column];
    }

    @Override
    public boolean isCellEditable(int row, int column) {
        // Only "Enabled" column is directly editable in the table
        return column == 0;
    }

    @Override
    public Object getValueAt(int row, int column) {
        if (row < 0 || row >= rules.size()) return null;
        MaskingRule rule = rules.get(row);
        switch (column) {
            case 0: return rule.isEnabled();
            case 1: return rule.getName();
            case 2: return rule.getCategory();
            case 3: return rule.getRegex();
            case 4: return String.valueOf(rule.getMaskChar());
            case 5: return rule.isBuiltIn();
            case 6: return rule.getDescription();
            default: return null;
        }
    }

    @Override
    public void setValueAt(Object value, int row, int column) {
        if (row < 0 || row >= rules.size()) return;
        MaskingRule rule = rules.get(row);
        if (column == 0 && value instanceof Boolean) {
            rule.setEnabled((Boolean) value);
            fireTableCellUpdated(row, column);
        }
    }

    /**
     * Get the rule at the specified row.
     */
    public MaskingRule getRuleAt(int row) {
        if (row >= 0 && row < rules.size()) {
            return rules.get(row);
        }
        return null;
    }

    /**
     * Refresh table data from the current rules list.
     */
    public void refresh() {
        fireTableDataChanged();
    }

    /**
     * Enable all rules in a specific category.
     */
    public void enableCategory(RuleCategory category, boolean enabled) {
        for (int i = 0; i < rules.size(); i++) {
            if (rules.get(i).getCategory() == category) {
                rules.get(i).setEnabled(enabled);
            }
        }
        fireTableDataChanged();
    }

    /**
     * Enable/disable all rules.
     */
    public void setAllEnabled(boolean enabled) {
        for (MaskingRule rule : rules) {
            rule.setEnabled(enabled);
        }
        fireTableDataChanged();
    }

    /**
     * Get count of enabled rules.
     */
    public int getEnabledCount() {
        return (int) rules.stream().filter(MaskingRule::isEnabled).count();
    }

    /**
     * Get total rule count.
     */
    public int getTotalCount() {
        return rules.size();
    }
}
