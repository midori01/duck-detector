#pragma once

#include <string>
#include <vector>

namespace systemproperties {

    struct PropAreaFinding {
        std::string context;
        int hole_count = 0;
        std::string detail;
    };

    struct PropAreaSnapshot {
        bool available = false;
        int context_count = 0;
        int hole_count = 0;
        std::vector<PropAreaFinding> findings;
    };

    PropAreaSnapshot scan_prop_area_holes();

}  // namespace systemproperties
