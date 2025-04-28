// Database Migration Helper

document.addEventListener('DOMContentLoaded', function() {
    // Check for database migration parameter in URL
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get('fix_database') === 'true') {
        fixDatabase();
    }
});

async function fixDatabase() {
    try {
        // First try the non-destructive migration
        console.log("Attempting database migration...");
        const response = await fetch('/migrate-database');
        const result = await response.json();
        
        if (result.success) {
            console.log("Database migration successful:", result.message);
            alert("Database migration successful: " + result.message);
        } else {
            console.error("Migration failed:", result.error);
            
            if (confirm("Non-destructive migration failed. Would you like to try recreating the database? WARNING: This will delete all existing data.")) {
                const resetResponse = await fetch('/fix-database');
                const resetResult = await resetResponse.json();
                
                if (resetResult.success) {
                    console.log("Database reset successful");
                    alert("Database has been reset and recreated successfully. All existing data has been removed.");
                } else {
                    console.error("Database reset failed:", resetResult.error);
                    alert("Database reset failed: " + resetResult.error);
                }
            }
        }
    } catch (error) {
        console.error("Error during database migration:", error);
        alert("Error during database migration. See console for details.");
    }
    
    // Remove the parameter from URL
    window.history.replaceState({}, document.title, window.location.pathname);
}

// Add utility functions for database management
window.dbUtils = {
    migrateDatabase: async function() {
        try {
            const response = await fetch('/migrate-database');
            const result = await response.json();
            return result;
        } catch (error) {
            console.error("Migration error:", error);
            return { success: false, error: error.message };
        }
    },
    
    resetDatabase: async function() {
        if (confirm("Are you sure you want to reset the database? This will delete ALL data.")) {
            try {
                const response = await fetch('/fix-database');
                const result = await response.json();
                return result;
            } catch (error) {
                console.error("Reset error:", error);
                return { success: false, error: error.message };
            }
        }
        return { success: false, cancelled: true };
    }
};
