<template>
  <div class="view-header d-flex align-center justify-space-between flex-wrap mb-6 ga-3">
    <div>
      <div class="text-overline text-primary">{{ overline }}</div>
      <div class="text-h4 font-weight-bold">{{ title }}</div>
      <div v-if="description" class="text-body-2 text-medium-emphasis">
        {{ description }}
      </div>
    </div>
    <div class="d-flex align-center ga-2 header-actions">
      <slot name="actions">
        <v-btn
          v-if="showRefresh"
          variant="outlined"
          color="primary"
          prepend-icon="mdi-refresh"
          :loading="refreshLoading"
          @click="$emit('refresh')"
        >
          {{ refreshLabel }}
        </v-btn>
      </slot>
    </div>
  </div>
</template>

<script>
export default {
  name: "ViewHeader",
  props: {
    overline: {
      type: String,
      default: "",
    },
    title: {
      type: String,
      required: true,
    },
    description: {
      type: String,
      default: "",
    },
    showRefresh: {
      type: Boolean,
      default: true,
    },
    refreshLabel: {
      type: String,
      default: "Refresh",
    },
    refreshLoading: {
      type: Boolean,
      default: false,
    },
  },
  emits: ["refresh"],
};
</script>

<style scoped>
.view-header {
  position: relative;
}

.view-header::after {
  content: "";
  position: absolute;
  left: 0;
  right: 0;
  bottom: -8px;
  height: 1px;
  background: linear-gradient(
    90deg,
    rgba(92, 193, 237, 0.55),
    rgba(92, 193, 237, 0.08),
    transparent
  );
}

.header-actions {
  min-height: 40px;
}
</style>
