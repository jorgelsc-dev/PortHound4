import sys

import settings


def _resolve_app_module():
    module = sys.modules.get("app")
    if module is not None:
        return module
    main_module = sys.modules.get("__main__")
    if (
        main_module is not None
        and str(getattr(main_module, "__file__", "") or "").endswith("app.py")
        and hasattr(main_module, "app")
    ):
        return main_module
    import app as imported_app_module

    return imported_app_module


app_module = _resolve_app_module()


def build_master_ssl_context():
    return None


def run_master_mode(enable_local_scanners=False):
    ssl_context = build_master_ssl_context()
    app_module.app.add_startup(app_module.register_frontend_dist_routes)
    app_module.app.add_startup(app_module.start_geoip_blocks_db)
    if not enable_local_scanners:
        app_module.app.add_startup(app_module.start_local_cluster_agent)
    if enable_local_scanners:
        app_module.app.add_startup(app_module.start_scanners)
    app_module.app.add_startup(app_module.start_scan_map_telemetry)
    app_module.app.add_startup(app_module.start_attack_telemetry)
    role_label = "standalone" if enable_local_scanners else "master"
    if not str(getattr(settings, "API_TOKEN", "") or "").strip():
        bind_host = str(getattr(settings, "HOST", "") or "").strip().lower()
        if bind_host not in {"127.0.0.1", "localhost", "::1"}:
            print(
                "[security] PORTHOUND_API_TOKEN is not set. "
                "Admin endpoints are restricted to loopback clients."
            )
    print(f"[bootstrap] role={role_label} host={settings.HOST} port={settings.PORT}")
    app_module.app.run(settings.HOST, settings.PORT, ssl_context=ssl_context)


def main():
    run_master_mode(enable_local_scanners=(app_module.current_role() == "standalone"))


if __name__ == "__main__":
    main()
