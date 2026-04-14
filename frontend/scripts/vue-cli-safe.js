#!/usr/bin/env node
"use strict";

// Vue CLI pulls in node-ipc, which may crash in restricted runtimes when
// querying network interfaces. Guard the call and return a safe fallback.
const os = require("os");
const originalNetworkInterfaces = os.networkInterfaces.bind(os);

os.networkInterfaces = function safeNetworkInterfaces() {
  try {
    const interfaces = originalNetworkInterfaces();
    if (interfaces && typeof interfaces === "object") {
      return interfaces;
    }
  } catch (_err) {
    // fallback below
  }

  return {
    lo: [{ family: "IPv4", address: "127.0.0.1", internal: true }],
  };
};

require("@vue/cli-service/bin/vue-cli-service");
