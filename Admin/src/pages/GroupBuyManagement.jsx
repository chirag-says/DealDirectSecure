import React from "react";
import { useNavigate } from "react-router-dom";
import { Users, ArrowRight } from "lucide-react";

/**
 * GroupBuyManagement — Redirect notice
 * 
 * The old Property-based Group Buy system has been retired.
 * Group Buy campaigns are now created per UnitType within Builder Projects.
 * Admin creates them from: Project Detail → Unit Type → "Create Campaign"
 */
export default function GroupBuyManagement() {
    const navigate = useNavigate();

    return (
        <div className="p-4 sm:p-8 min-h-screen bg-gray-50/30 w-full max-w-full mx-auto">
            <div className="max-w-xl mx-auto mt-16 text-center">
                <div className="inline-flex p-4 bg-indigo-50 text-indigo-600 rounded-2xl mb-6">
                    <Users className="w-12 h-12" />
                </div>
                <h1 className="text-2xl font-bold text-gray-900 mb-3">
                    Group Buy Has Moved
                </h1>
                <p className="text-gray-500 mb-6 leading-relaxed">
                    Group Buy campaigns are now managed at the <strong>Project → Unit Type</strong> level.
                    To create or manage a Group Buy campaign, go to any Builder Project and click
                    <strong> "Create Campaign" </strong> on a unit type.
                </p>
                <button
                    onClick={() => navigate("/builder-management")}
                    className="inline-flex items-center gap-2 px-6 py-3 bg-indigo-600 text-white rounded-xl text-sm font-semibold hover:bg-indigo-700 transition-all shadow-sm"
                >
                    Go to Builder Management <ArrowRight className="w-4 h-4" />
                </button>
            </div>
        </div>
    );
}
