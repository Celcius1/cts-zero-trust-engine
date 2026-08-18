// ==============================================================================
// CTS ZERO TRUST ENGINE SOFTWARE MASTER SDUI (HEADER)
// Copyright (c) 2026 Cel-Tech-Serv Pty Ltd. All Rights Reserved.
// ==============================================================================
// INSTRUCTIONS FOR COPYING: 
// 1. Overwrite your previous sdui.hpp with this updated version.
// 2. The ActionType enum has been stripped of client-side execution 
//    methods to enforce the "dumb renderer" architecture.
// ==============================================================================

#pragma once
#include <string>
#include <vector>
#include <memory>
#include "nlohmann/json.hpp"

namespace CTS {
namespace SDUI {

    // --------------------------------------------------------------------------
    // ACTION BEHAVIOUR ENUMERATION
    // Defines how the Avalonia client should interact with the C++ backend.
    // Stripped of NativeModule and WebView to enforce a dumb renderer model.
    // --------------------------------------------------------------------------
    enum class ActionType {
        ApiCall_Active,   // Makes a REST call that REFRESHES the user's idle timeout
        ApiCall_Silent    // Makes a REST call WITHOUT refreshing the timeout (Polling)
    };

    // --------------------------------------------------------------------------
    // BASE COMPONENT CONTRACT
    // --------------------------------------------------------------------------
    class Component {
    public:
        virtual ~Component() = default;
        
        // Serialises the component into the JSON payload
        virtual nlohmann::json to_json() const = 0;
    };

    using ComponentPtr = std::shared_ptr<Component>;

    // --------------------------------------------------------------------------
    // DATA GRID COMPONENT (For OSL Ledgers / OSSC File Managers)
    // --------------------------------------------------------------------------
    class DataGrid : public Component {
    private:
        std::string grid_id;
        std::vector<std::string> columns;
        std::string fetch_endpoint; 
        ActionType refresh_behaviour;

    public:
        DataGrid(const std::string& id, const std::string& endpoint, ActionType behaviour = ActionType::ApiCall_Active);
        
        void add_column(const std::string& header_name);
        nlohmann::json to_json() const override;
    };

    // --------------------------------------------------------------------------
    // TAB PANEL COMPONENT
    // Represents a single tab page (e.g., "OSL Permissions", "OSSC Access").
    // --------------------------------------------------------------------------
    class TabPanel : public Component {
    private:
        std::string title;
        ComponentPtr content;

    public:
        TabPanel(const std::string& tab_title, ComponentPtr tab_content);
        nlohmann::json to_json() const override;
    };

    // --------------------------------------------------------------------------
    // TAB CONTROL COMPONENT
    // The master container that holds multiple TabPanels.
    // --------------------------------------------------------------------------
    class TabControl : public Component {
    private:
        std::vector<ComponentPtr> tabs;

    public:
        TabControl() = default;
        
        void add_tab(ComponentPtr tab);
        nlohmann::json to_json() const override;
    };

    // --------------------------------------------------------------------------
    // ACTION BUTTON COMPONENT
    // --------------------------------------------------------------------------
    class Button : public Component {
    private:
        std::string label;
        std::string endpoint;
        ActionType behaviour;
        std::string style_class;

    public:
        Button(const std::string& btn_label, const std::string& target_endpoint, ActionType type, const std::string& css_class = "primary");
        nlohmann::json to_json() const override;
    };

    // --------------------------------------------------------------------------
    // APP BUILDER UTILITY
    // The main wrapper that generates the final JSON file for sdui_apps.d/
    // --------------------------------------------------------------------------
    class AppLayout {
    private:
        std::string app_id;
        std::string app_title;
        ComponentPtr root_component;

    public:
        AppLayout(const std::string& id, const std::string& title);
        
        void set_root(ComponentPtr root);
        
        std::string render() const;
    };

} // namespace SDUI
} // namespace CTS