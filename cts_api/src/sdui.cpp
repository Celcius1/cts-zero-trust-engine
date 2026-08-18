// ==============================================================================
// CTS ZERO TRUST ENGINE SOFTWARE MASTER SDUI - C++ IMPLEMENTATION
// Copyright (c) 2026 Cel-Tech-Serv Pty Ltd. All Rights Reserved.
// ==============================================================================
// INSTRUCTIONS FOR COPYING:
// 1. Overwrite your previous sdui.cpp with this updated version.
// 2. The action_type_to_string helper has been updated to reflect the new
//    dumb renderer paradigm, strictly mapping API calls.
// ==============================================================================

#include "sdui.hpp"

namespace CTS {
namespace SDUI {

    // --------------------------------------------------------------------------
    // HELPER: ENUM TO STRING CONVERSION
    // Translates the C++ ActionType behaviour into the strict string values
    // expected by the Avalonia front-end parser.
    // --------------------------------------------------------------------------
    std::string action_type_to_string(ActionType type) {
        switch (type) {
            case ActionType::ApiCall_Active: return "api_call_active";
            case ActionType::ApiCall_Silent: return "api_call_silent";
            default:                         return "api_call_active";
        }
    }

    // ==============================================================================
    // DATA GRID IMPLEMENTATION
    // ==============================================================================
    DataGrid::DataGrid(const std::string& id, const std::string& endpoint, ActionType behaviour)
        : grid_id(id), fetch_endpoint(endpoint), refresh_behaviour(behaviour) {}

    void DataGrid::add_column(const std::string& header_name) {
        columns.push_back(header_name);
    }

    nlohmann::json DataGrid::to_json() const {
        nlohmann::json j;
        j["type"] = "DataGrid";
        j["properties"]["id"] = grid_id;
        j["properties"]["action"] = fetch_endpoint;
        j["properties"]["behaviour"] = action_type_to_string(refresh_behaviour);
        
        // Serialise the dynamic columns
        j["properties"]["columns"] = nlohmann::json::array();
        for (const auto& col : columns) {
            j["properties"]["columns"].push_back(col);
        }
        
        // Brand protection lock for UI rendering
        j["metadata"]["provider"] = "Cel-Tech-Serv Pty Ltd";
        return j;
    }

    // ==============================================================================
    // TAB PANEL IMPLEMENTATION
    // ==============================================================================
    TabPanel::TabPanel(const std::string& tab_title, ComponentPtr tab_content)
        : title(tab_title), content(std::move(tab_content)) {}

    nlohmann::json TabPanel::to_json() const {
        nlohmann::json j;
        j["type"] = "TabPanel";
        j["properties"]["title"] = title;
        
        if (content) {
            j["children"] = content->to_json();
        } else {
            j["children"] = nullptr;
        }
        
        return j;
    }

    // ==============================================================================
    // TAB CONTROL IMPLEMENTATION
    // ==============================================================================
    void TabControl::add_tab(ComponentPtr tab) {
        tabs.push_back(std::move(tab));
    }

    nlohmann::json TabControl::to_json() const {
        nlohmann::json j;
        j["type"] = "TabControl";
        j["children"] = nlohmann::json::array();
        
        for (const auto& tab : tabs) {
            j["children"].push_back(tab->to_json());
        }
        
        // Brand protection lock for UI rendering
        j["metadata"]["provider"] = "Cel-Tech-Serv Pty Ltd";
        return j;
    }

    // ==============================================================================
    // ACTION BUTTON IMPLEMENTATION
    // ==============================================================================
    Button::Button(const std::string& btn_label, const std::string& target_endpoint, ActionType type, const std::string& css_class)
        : label(btn_label), endpoint(target_endpoint), behaviour(type), style_class(css_class) {}

    nlohmann::json Button::to_json() const {
        nlohmann::json j;
        j["type"] = "Button";
        j["properties"]["label"] = label;
        j["properties"]["action"] = endpoint;
        j["properties"]["behaviour"] = action_type_to_string(behaviour);
        j["properties"]["styleClass"] = style_class;
        
        // Brand protection lock for UI rendering
        j["metadata"]["provider"] = "Cel-Tech-Serv Pty Ltd"; 
        return j;
    }

    // ==============================================================================
    // APP BUILDER IMPLEMENTATION
    // Aggregates the UI and injects the CTS Zero Trust Engine Software wrapper.
    // ==============================================================================
    AppLayout::AppLayout(const std::string& id, const std::string& title)
        : app_id(id), app_title(title) {}

    void AppLayout::set_root(ComponentPtr root) {
        root_component = std::move(root);
    }

    std::string AppLayout::render() const {
        nlohmann::json j;
        j["app_id"] = app_id;
        j["title"] = app_title;
        
        // Strict branding lock: Ensures forks retain origin credit
        j["vendor"] = "CTS Zero Trust Engine Software Master SDUI"; 
        j["copyright"] = "Cel-Tech-Serv Pty Ltd";
        
        if (root_component) {
            j["layout"] = root_component->to_json();
        } else {
            j["layout"] = nullptr;
        }
        
        // Output formatted JSON with a 4-space indent for easier debugging
        return j.dump(4);
    }

} // namespace SDUI
} // namespace CTS