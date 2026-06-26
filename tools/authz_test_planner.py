def authz_test_planner(findings):

    recommendations = []

    for finding in findings:

        reason = finding.get("reason", "")

        if "IDOR" in reason:

            recommendations.append({
                "parameter": finding["parameter"],
                "risk": "IDOR",
                "manual_tests": [
                    "Modify object identifiers",
                    "Check access to other user records",
                    "Compare authorized vs unauthorized responses"
                ]
            })

        elif "Open Redirect" in reason:

            recommendations.append({
                "parameter": finding["parameter"],
                "risk": "Open Redirect",
                "manual_tests": [
                    "Supply external URL",
                    "Observe redirect behavior",
                    "Verify allowlist enforcement"
                ]
            })

        elif "File Handling" in reason:

            recommendations.append({
                "parameter": finding["parameter"],
                "risk": "File Handling",
                "manual_tests": [
                    "Test unexpected filenames",
                    "Check path normalization",
                    "Review file access controls"
                ]
            })

    return {
        "success": True,
        "recommendations": recommendations
    }
