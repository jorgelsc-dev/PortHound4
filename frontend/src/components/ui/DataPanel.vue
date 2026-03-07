<template>
  <v-card :variant="variant" class="pa-6 data-panel">
    <div
      v-if="showHeader"
      class="d-flex align-center justify-space-between flex-wrap ga-2 mb-4 panel-head"
    >
      <div class="d-flex align-center ga-3">
        <span class="panel-pulse"></span>
        <div>
          <div class="text-subtitle-1 font-weight-medium">{{ title }}</div>
          <div v-if="subtitle" class="text-body-2 text-medium-emphasis">
            {{ subtitle }}
          </div>
        </div>
      </div>
      <div class="d-flex align-center ga-2">
        <v-chip v-if="lastUpdated" size="small" variant="outlined" color="info">
          {{ lastUpdated }}
        </v-chip>
        <v-btn
          v-if="showRefresh"
          size="small"
          variant="outlined"
          color="primary"
          prepend-icon="mdi-refresh"
          :loading="loading"
          @click="$emit('refresh')"
        >
          {{ refreshLabel }}
        </v-btn>
      </div>
    </div>

    <v-alert v-if="error" type="error" variant="tonal" class="mb-4">
      {{ error }}
    </v-alert>

    <v-progress-linear
      v-if="loading"
      color="primary"
      indeterminate
      height="3"
      rounded
      class="panel-loader mb-3"
    />

    <div class="panel-body">
      <div
        v-if="!loading || keepContentOnLoading"
        class="panel-content"
        :class="{ 'panel-content--loading': loading && keepContentOnLoading }"
      >
        <slot />
      </div>

      <transition name="panel-fade">
        <div
          v-if="loading"
          class="panel-skeleton"
          :class="{ 'panel-skeleton--overlay': keepContentOnLoading }"
        >
          <slot name="skeleton">
            <div class="panel-skeleton__frame">
              <div class="panel-skeleton__chrome">
                <div class="panel-skeleton__dot" />
                <div class="panel-skeleton__headlines">
                  <div class="skeleton-line skeleton-line--title" />
                  <div class="skeleton-line skeleton-line--quarter" />
                </div>
                <div class="panel-skeleton__badge" />
              </div>

              <div class="panel-skeleton__grid">
                <div class="panel-skeleton__module panel-skeleton__module--hero">
                  <div class="skeleton-line skeleton-line--wide" />
                  <div class="skeleton-line" />
                  <div class="skeleton-line skeleton-line--half" />
                </div>
                <div class="panel-skeleton__module">
                  <div class="skeleton-line skeleton-line--micro" />
                  <div class="skeleton-line skeleton-line--metric" />
                  <div class="skeleton-line skeleton-line--half" />
                </div>
                <div class="panel-skeleton__module">
                  <div class="skeleton-line skeleton-line--micro" />
                  <div class="skeleton-line skeleton-line--metric" />
                  <div class="skeleton-line skeleton-line--quarter" />
                </div>
              </div>
            </div>
          </slot>
        </div>
      </transition>
    </div>
  </v-card>
</template>

<script>
export default {
  name: "DataPanel",
  props: {
    title: {
      type: String,
      required: true,
    },
    subtitle: {
      type: String,
      default: "",
    },
    loading: {
      type: Boolean,
      default: false,
    },
    keepContentOnLoading: {
      type: Boolean,
      default: true,
    },
    error: {
      type: String,
      default: "",
    },
    lastUpdated: {
      type: String,
      default: "",
    },
    showRefresh: {
      type: Boolean,
      default: false,
    },
    showHeader: {
      type: Boolean,
      default: true,
    },
    refreshLabel: {
      type: String,
      default: "Refresh",
    },
    variant: {
      type: String,
      default: "outlined",
    },
  },
  emits: ["refresh"],
};
</script>

<style scoped>
.data-panel {
  border-radius: 18px;
  overflow: hidden;
}

.panel-head {
  padding-bottom: 10px;
  border-bottom: 1px solid rgba(104, 178, 221, 0.14);
}

.panel-pulse {
  width: 10px;
  height: 10px;
  border-radius: 999px;
  background: rgba(103, 205, 248, 0.9);
  box-shadow: 0 0 0 0 rgba(103, 205, 248, 0.32);
  animation: panel-pulse 2.1s ease-in-out infinite;
}

.panel-body {
  position: relative;
  min-height: 78px;
}

.panel-loader {
  opacity: 0.88;
}

.panel-content {
  transition: opacity 0.18s ease;
}

.panel-content--loading {
  opacity: 0.52;
}

.panel-skeleton {
  border: 1px solid rgba(104, 180, 226, 0.18);
  border-radius: 16px;
  padding: 16px;
  background: linear-gradient(
    150deg,
    rgba(7, 13, 21, 0.92) 0%,
    rgba(9, 18, 30, 0.82) 48%,
    rgba(5, 11, 19, 0.9) 100%
  );
  position: relative;
  overflow: hidden;
  box-shadow: inset 0 1px 0 rgba(132, 205, 241, 0.08), 0 18px 34px rgba(2, 8, 14, 0.28);
}

.panel-skeleton::before {
  content: "";
  position: absolute;
  inset: 0;
  background-image: linear-gradient(rgba(126, 177, 217, 0.06) 1px, transparent 1px),
    linear-gradient(90deg, rgba(126, 177, 217, 0.05) 1px, transparent 1px);
  background-size: 26px 26px;
  opacity: 0.24;
  mask-image: linear-gradient(180deg, rgba(0, 0, 0, 0.9), transparent 100%);
  pointer-events: none;
}

.panel-skeleton::after {
  content: "";
  position: absolute;
  inset: 0;
  background: linear-gradient(
    110deg,
    rgba(24, 40, 58, 0) 0%,
    rgba(93, 168, 216, 0.1) 26%,
    rgba(120, 224, 255, 0.22) 48%,
    rgba(24, 40, 58, 0) 90%
  );
  animation: panel-shimmer 1.4s linear infinite;
  pointer-events: none;
}

.panel-skeleton--overlay {
  position: absolute;
  inset: 0;
  padding: 16px;
  border: 0;
  border-radius: 16px;
  background: rgba(6, 11, 18, 0.68);
  backdrop-filter: blur(6px);
}

.panel-skeleton__frame {
  display: grid;
  gap: 16px;
  position: relative;
  z-index: 1;
}

.panel-skeleton__chrome {
  display: grid;
  grid-template-columns: auto 1fr auto;
  align-items: center;
  gap: 12px;
}

.panel-skeleton__dot {
  width: 12px;
  height: 12px;
  border-radius: 999px;
  background: radial-gradient(circle at 35% 35%, rgba(145, 244, 255, 0.98), rgba(46, 172, 223, 0.78));
  box-shadow: 0 0 18px rgba(65, 206, 255, 0.35);
}

.panel-skeleton__headlines {
  display: grid;
  gap: 10px;
}

.panel-skeleton__badge {
  width: 88px;
  height: 24px;
  border-radius: 999px;
  background: linear-gradient(90deg, rgba(62, 112, 154, 0.32), rgba(111, 190, 232, 0.44));
  background-size: 220% 100%;
  animation: skeleton-slide 1.2s ease-in-out infinite;
  box-shadow: inset 0 0 0 1px rgba(123, 195, 234, 0.14);
}

.panel-skeleton__grid {
  display: grid;
  gap: 12px;
  grid-template-columns: minmax(0, 1.8fr) repeat(2, minmax(0, 1fr));
}

.panel-skeleton__module {
  min-height: 88px;
  padding: 14px;
  border-radius: 14px;
  border: 1px solid rgba(110, 183, 225, 0.12);
  background: linear-gradient(180deg, rgba(15, 27, 42, 0.5), rgba(8, 15, 24, 0.72));
  display: grid;
  align-content: start;
  gap: 12px;
}

.panel-skeleton__module--hero {
  min-height: 118px;
}

.skeleton-line {
  height: 12px;
  border-radius: 999px;
  background: linear-gradient(
    90deg,
    rgba(47, 95, 138, 0.34),
    rgba(122, 210, 244, 0.44),
    rgba(47, 95, 138, 0.34)
  );
  background-size: 220% 100%;
  animation: skeleton-slide 1.2s ease-in-out infinite;
  box-shadow: inset 0 0 0 1px rgba(126, 187, 225, 0.05);
}

.skeleton-line--title {
  width: 42%;
  height: 15px;
}

.skeleton-line--half {
  width: 66%;
}

.skeleton-line--quarter {
  width: 26%;
}

.skeleton-line--wide {
  width: 84%;
}

.skeleton-line--micro {
  width: 28%;
  height: 10px;
}

.skeleton-line--metric {
  width: 72%;
  height: 20px;
}

.panel-fade-enter-active,
.panel-fade-leave-active {
  transition: opacity 0.2s ease;
}

.panel-fade-enter-from,
.panel-fade-leave-to {
  opacity: 0;
}

@keyframes panel-shimmer {
  from {
    transform: translateX(-100%);
  }
  to {
    transform: translateX(100%);
  }
}

@keyframes skeleton-slide {
  0% {
    background-position: 100% 0;
  }
  100% {
    background-position: -120% 0;
  }
}

@keyframes panel-pulse {
  0%,
  100% {
    box-shadow: 0 0 0 0 rgba(103, 205, 248, 0.3);
  }
  50% {
    box-shadow: 0 0 0 8px rgba(103, 205, 248, 0);
  }
}

@media (max-width: 960px) {
  .panel-skeleton__grid {
    grid-template-columns: 1fr;
  }

  .panel-skeleton__module,
  .panel-skeleton__module--hero {
    min-height: 82px;
  }
}
</style>
