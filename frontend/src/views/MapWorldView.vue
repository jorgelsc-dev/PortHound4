<template>
  <div class="atlas-view">
    <section class="atlas-stage atlas-stage--full">
      <MapPanel
        class="atlas-panel"
        :map-only="true"
        :immersive="true"
        :show-refresh="true"
        :show-panel-header="false"
        :show-intro="false"
        :show-projection-switch="true"
        default-projection="flat"
        panel-title="World Scan Atlas"
        panel-subtitle="Full-screen telemetry stage with flat and globe projections, auto-rotation, and animated route traces."
      />
    </section>
  </div>
</template>

<script>
import MapPanel from "../components/MapPanel.vue";

export default {
  name: "MapWorldView",
  components: {
    MapPanel,
  },
};
</script>

<style scoped>
.atlas-view {
  position: relative;
}

.atlas-stage {
  position: relative;
  overflow: hidden;
  min-height: calc(100vh - 84px);
  border: 1px solid rgba(88, 174, 214, 0.22);
  border-radius: 30px;
  padding: 8px;
  background:
    radial-gradient(90% 120% at 0% 0%, rgba(57, 151, 203, 0.22), transparent 58%),
    radial-gradient(80% 120% at 100% 0%, rgba(255, 166, 88, 0.12), transparent 58%),
    linear-gradient(145deg, rgba(7, 14, 26, 0.98), rgba(3, 8, 16, 0.98));
  box-shadow:
    0 28px 60px rgba(3, 8, 16, 0.42),
    inset 0 0 0 1px rgba(255, 255, 255, 0.03);
}

.atlas-stage::before {
  content: "";
  position: absolute;
  inset: 0;
  pointer-events: none;
  background:
    linear-gradient(90deg, rgba(92, 194, 237, 0.08) 1px, transparent 1px),
    linear-gradient(180deg, rgba(92, 194, 237, 0.05) 1px, transparent 1px);
  background-size: 24px 24px;
  mask-image: linear-gradient(180deg, rgba(0, 0, 0, 0.92), transparent);
  opacity: 0.3;
}

.atlas-stage::after {
  content: "";
  position: absolute;
  left: -10%;
  right: -10%;
  top: 0;
  height: 2px;
  background: linear-gradient(
    90deg,
    rgba(76, 233, 184, 0),
    rgba(76, 233, 184, 0.58),
    rgba(76, 233, 184, 0)
  );
  box-shadow: 0 0 26px rgba(76, 233, 184, 0.24);
  animation: atlas-stage-scan 7.4s linear infinite;
  pointer-events: none;
}

.atlas-panel {
  position: relative;
  z-index: 1;
}

.atlas-panel :deep(.data-panel) {
  min-height: calc(100vh - 100px);
  border-radius: 24px;
  border-color: rgba(96, 182, 223, 0.2);
  background:
    radial-gradient(100% 140% at 8% 0%, rgba(64, 149, 206, 0.12), transparent 48%),
    linear-gradient(180deg, rgba(4, 12, 23, 0.96), rgba(4, 10, 18, 0.96));
}

.atlas-panel :deep(.data-panel) {
  padding: 10px !important;
}

.atlas-panel :deep(.panel-body) {
  min-height: 0;
}

.atlas-panel :deep(.map-wrapper) {
  margin-top: 0 !important;
  border-radius: 26px;
  border-color: rgba(96, 182, 223, 0.24);
  box-shadow:
    inset 0 0 0 1px rgba(255, 255, 255, 0.03),
    inset 0 44px 120px rgba(44, 139, 206, 0.08),
    0 26px 70px rgba(3, 8, 16, 0.46);
}

.atlas-panel :deep(.map-wrapper::after) {
  opacity: 0.7;
}

.atlas-panel :deep(.map-legend) {
  right: 18px;
  bottom: 18px;
}

@keyframes atlas-stage-scan {
  from {
    transform: translateY(0);
  }
  to {
    transform: translateY(960px);
  }
}

@media (max-width: 960px) {
  .atlas-stage {
    min-height: calc(100vh - 76px);
    padding: 6px;
  }

  .atlas-panel :deep(.data-panel) {
    min-height: calc(100vh - 88px);
  }
}

@media (max-width: 760px) {
  .atlas-stage {
    border-radius: 22px;
    padding: 4px;
  }

  .atlas-panel :deep(.data-panel),
  .atlas-panel :deep(.map-wrapper) {
    border-radius: 18px;
  }
}
</style>
