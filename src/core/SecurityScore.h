#pragma once

#include "Severity.h"
#include "Finding.h"

#include <vector>
#include <algorithm>
#include <format>
#include <string>

namespace sentinel::core {

struct SecurityScoreBreakdown {
    int baseScore{100};
    int criticalCount{0};
    int highCount{0};
    int mediumCount{0};
    int lowCount{0};
    int infoCount{0};

    int criticalDeductions{0};
    int highDeductions{0};
    int mediumDeductions{0};
    int lowDeductions{0};

    int finalScore{100};

    [[nodiscard]] std::string explain() const {
        return std::format(
            "Base score: {}\n"
            "Critical findings ({}): -{}\n"
            "High findings ({}): -{}\n"
            "Medium findings ({}): -{}\n"
            "Low findings ({}): -{}\n"
            "Total deductions: -{}\n"
            "Final score: {}",
            baseScore,
            criticalCount, criticalDeductions,
            highCount, highDeductions,
            mediumCount, mediumDeductions,
            lowCount, lowDeductions,
            (criticalDeductions + highDeductions + mediumDeductions + lowDeductions),
            finalScore
        );
    }
};

class SecurityScoreCalculator {
public:
    static SecurityScoreBreakdown calculate(const std::vector<Finding>& findings, int baseScore = 100) {
        SecurityScoreBreakdown b;
        b.baseScore = baseScore;

        for (const auto& f : findings) {
            switch (f.severity) {
                case Severity::Critical:
                    b.criticalCount++;
                    b.criticalDeductions += severityScorePenalty(Severity::Critical);
                    break;
                case Severity::High:
                    b.highCount++;
                    b.highDeductions += severityScorePenalty(Severity::High);
                    break;
                case Severity::Medium:
                    b.mediumCount++;
                    b.mediumDeductions += severityScorePenalty(Severity::Medium);
                    break;
                case Severity::Low:
                    b.lowCount++;
                    b.lowDeductions += severityScorePenalty(Severity::Low);
                    break;
                case Severity::Info:
                    b.infoCount++;
                    break;
            }
        }

        int totalPenalty = b.criticalDeductions + b.highDeductions + b.mediumDeductions + b.lowDeductions;
        b.finalScore = std::clamp(b.baseScore - totalPenalty, 0, 100);
        return b;
    }
};

} // namespace sentinel::core
