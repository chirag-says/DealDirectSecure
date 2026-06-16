/**
 * Format a raw price (in ₹) into a readable Indian real-estate format.
 *
 * Examples:
 *   70000000  → "₹7 Crore"
 *   15000000  → "₹1.5 Crore"
 *   5000000   → "₹50 Lakh"
 *   4000000   → "₹40 Lakh"
 *   150000    → "₹1.50 Lakh"
 *   18000     → "₹18,000"
 *   10000     → "₹10,000"
 *
 * @param {number|string} price — raw price value in rupees
 * @returns {string}            — formatted price string with ₹ prefix
 */
export function formatPrice(price) {
    const amount = Number(price) || 0;
    if (amount <= 0) return "₹0";

    if (amount >= 10000000) {
        // 1 Crore = 10,000,000
        const croreVal = amount / 10000000;
        const formatted = croreVal % 1 === 0
            ? croreVal.toFixed(0)
            : croreVal.toFixed(2).replace(/0+$/, '').replace(/\.$/, '');
        return `₹${formatted} Crore`;
    }

    if (amount >= 100000) {
        // 1 Lakh = 100,000
        const lacVal = amount / 100000;
        const formatted = lacVal % 1 === 0
            ? lacVal.toFixed(0)
            : lacVal.toFixed(2).replace(/0+$/, '').replace(/\.$/, '');
        return `₹${formatted} Lakh`;
    }

    // Below 1 Lakh — show full formatted number with Indian grouping
    return `₹${amount.toLocaleString('en-IN')}`;
}

/**
 * Returns the formatted numeric string and the unit label separately.
 * Useful when you need to render the unit in a different visual style.
 *
 * Examples:
 *   70000000  → { value: "₹7",    unit: "Crore" }
 *   5000000   → { value: "₹50",   unit: "Lakh"   }
 *   150000    → { value: "₹1.50", unit: "Lakh"   }
 *   18000     → { value: "₹18,000", unit: ""    }
 *
 * @param {number|string} price — raw price value in rupees
 * @returns {{ value: string, unit: string }}
 */
export function formatPriceParts(price) {
    const amount = Number(price) || 0;
    if (amount <= 0) return { value: "₹0", unit: "" };

    if (amount >= 10000000) {
        const croreVal = amount / 10000000;
        const formatted = croreVal % 1 === 0
            ? croreVal.toFixed(0)
            : croreVal.toFixed(2).replace(/0+$/, '').replace(/\.$/, '');
        return { value: `₹${formatted}`, unit: "Crore" };
    }

    if (amount >= 100000) {
        const lacVal = amount / 100000;
        const formatted = lacVal % 1 === 0
            ? lacVal.toFixed(0)
            : lacVal.toFixed(2).replace(/0+$/, '').replace(/\.$/, '');
        return { value: `₹${formatted}`, unit: "Lakh" };
    }

    return { value: `₹${amount.toLocaleString('en-IN')}`, unit: "" };
}
