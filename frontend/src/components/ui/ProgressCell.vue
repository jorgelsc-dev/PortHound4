<template>
  <div class="progress-cell">
    <v-progress-linear
      :model-value="normalized"
      :color="barColor"
      bg-color="rgba(124, 145, 165, 0.28)"
      height="8"
      rounded
    />
    <span class="progress-label">{{ label }}</span>
  </div>
</template>

<script>
export default {
  name: "ProgressCell",
  props: {
    value: {
      type: [Number, String],
      default: 0,
    },
    showDecimals: {
      type: Boolean,
      default: false,
    },
  },
  computed: {
    normalized() {
      const parsed = Number.parseFloat(this.value);
      if (!Number.isFinite(parsed)) return 0;
      if (parsed < 0) return 0;
      if (parsed > 100) return 100;
      return parsed;
    },
    label() {
      if (this.showDecimals) {
        return `${this.normalized.toFixed(1)}%`;
      }
      return `${Math.round(this.normalized)}%`;
    },
    barColor() {
      if (this.normalized >= 95) return "success";
      if (this.normalized >= 70) return "info";
      if (this.normalized >= 40) return "warning";
      return "error";
    },
  },
};
</script>

<style scoped>
.progress-cell {
  min-width: 140px;
  display: grid;
  grid-template-columns: 1fr auto;
  align-items: center;
  gap: 10px;
}

.progress-label {
  font-size: 12px;
  color: rgba(226, 238, 250, 0.9);
  font-variant-numeric: tabular-nums;
}
</style>
