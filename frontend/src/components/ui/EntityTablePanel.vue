<template>
  <DataPanel
    :title="title"
    :subtitle="subtitle"
    :loading="loading"
    :error="error"
    :last-updated="lastUpdated"
    :show-refresh="showRefresh"
    :live-refresh="liveRefresh"
    :refresh-label="refreshLabel"
    :variant="variant"
    @refresh="$emit('refresh')"
  >
    <template #skeleton>
      <div class="table-skeleton">
        <div class="table-skeleton__head" :style="skeletonGridStyle">
          <span
            v-for="columnIndex in skeletonColumnCount"
            :key="`head-${columnIndex}`"
            class="table-skeleton__head-cell"
          />
        </div>
        <div
          v-for="rowIndex in skeletonRows"
          :key="`row-${rowIndex}`"
          class="table-skeleton__row"
          :style="skeletonGridStyle"
        >
          <span
            v-for="columnIndex in skeletonColumnCount"
            :key="`cell-${rowIndex}-${columnIndex}`"
            class="table-skeleton__cell"
            :style="skeletonCellStyle(rowIndex, columnIndex)"
          />
        </div>
      </div>
    </template>

    <v-table density="compact" class="entity-table mt-1">
      <thead>
        <tr>
          <th v-for="column in columns" :key="column.key">
            {{ column.label }}
          </th>
        </tr>
      </thead>
      <tbody>
        <tr
          v-for="(item, index) in displayRows"
          :key="resolveRowKey(item, index)"
        >
          <td
            v-for="column in columns"
            :key="`${resolveRowKey(item, index)}-${column.key}`"
          >
            <slot
              :name="`cell-${column.key}`"
              :item="item"
              :value="resolveValue(item, column)"
            >
              {{ formatValue(item, column) }}
            </slot>
          </td>
        </tr>
        <tr v-if="!normalizedRows.length">
          <td :colspan="columns.length" class="text-medium-emphasis py-4 text-center">
            {{ emptyText }}
          </td>
        </tr>
      </tbody>
    </v-table>
    <div class="d-flex justify-center mt-3" v-if="showPaginationControl">
      <v-pagination
        v-model="currentPage"
        :length="pageCount"
        density="comfortable"
        total-visible="7"
      />
    </div>
  </DataPanel>
</template>

<script>
import DataPanel from "./DataPanel.vue";

function getByPath(item, path) {
  if (!item || !path) return "";
  if (!String(path).includes(".")) {
    return item[path];
  }
  return String(path)
    .split(".")
    .reduce((acc, key) => (acc && acc[key] !== undefined ? acc[key] : undefined), item);
}

export default {
  name: "EntityTablePanel",
  components: { DataPanel },
  props: {
    title: {
      type: String,
      required: true,
    },
    subtitle: {
      type: String,
      default: "",
    },
    rows: {
      type: Array,
      default: () => [],
    },
    columns: {
      type: Array,
      default: () => [],
    },
    loading: {
      type: Boolean,
      default: false,
    },
    error: {
      type: String,
      default: "",
    },
    emptyText: {
      type: String,
      default: "No data",
    },
    rowKey: {
      type: String,
      default: "id",
    },
    showRefresh: {
      type: Boolean,
      default: false,
    },
    liveRefresh: {
      type: Boolean,
      default: false,
    },
    refreshLabel: {
      type: String,
      default: "Refresh",
    },
    lastUpdated: {
      type: String,
      default: "",
    },
    skeletonRows: {
      type: Number,
      default: 6,
    },
    enablePagination: {
      type: Boolean,
      default: true,
    },
    pageSize: {
      type: Number,
      default: 50,
    },
    variant: {
      type: String,
      default: "outlined",
    },
  },
  emits: ["refresh"],
  data() {
    return {
      currentPage: 1,
    };
  },
  computed: {
    normalizedRows() {
      return Array.isArray(this.rows) ? this.rows : [];
    },
    safePageSize() {
      const parsed = Number(this.pageSize);
      if (!Number.isFinite(parsed) || parsed <= 0) return 50;
      return Math.floor(parsed);
    },
    pageCount() {
      return Math.max(1, Math.ceil(this.normalizedRows.length / this.safePageSize));
    },
    showPaginationControl() {
      return this.enablePagination && this.pageCount > 1;
    },
    displayRows() {
      if (!this.enablePagination) {
        return this.normalizedRows;
      }
      const page = Math.min(Math.max(Number(this.currentPage) || 1, 1), this.pageCount);
      const start = (page - 1) * this.safePageSize;
      return this.normalizedRows.slice(start, start + this.safePageSize);
    },
    skeletonColumnCount() {
      const columns = Number(this.columns.length || 0);
      if (!Number.isFinite(columns) || columns <= 0) return 4;
      return Math.max(3, columns);
    },
    skeletonGridStyle() {
      return {
        gridTemplateColumns: `repeat(${this.skeletonColumnCount}, minmax(0, 1fr))`,
      };
    },
  },
  watch: {
    rows() {
      if (this.currentPage > this.pageCount) {
        this.currentPage = this.pageCount;
      }
    },
    pageSize() {
      this.currentPage = 1;
    },
  },
  methods: {
    resolveRowKey(item, index) {
      if (item && item[this.rowKey] !== undefined) {
        return String(item[this.rowKey]);
      }
      return `row-${index}`;
    },
    resolveValue(item, column) {
      const key = column && column.key ? column.key : "";
      return getByPath(item, key);
    },
    formatValue(item, column) {
      const value = this.resolveValue(item, column);
      if (column && typeof column.format === "function") {
        return column.format(value, item);
      }
      if (value === null || value === undefined || value === "") {
        return "-";
      }
      return value;
    },
    skeletonCellStyle(rowIndex, columnIndex) {
      const seed = ((rowIndex * 41) + (columnIndex * 17)) % 34;
      const width = 56 + seed;
      return { width: `${Math.min(width, 94)}%` };
    },
  },
};
</script>

<style scoped>
.entity-table {
  border-radius: 12px;
  overflow: hidden;
}

.entity-table :deep(thead th) {
  position: sticky;
  top: 0;
  z-index: 1;
  backdrop-filter: blur(8px);
}

.entity-table :deep(tbody tr) {
  transition: background-color 0.16s ease, transform 0.16s ease;
}

.entity-table :deep(tbody td) {
  border-bottom: 1px solid rgba(99, 173, 219, 0.1);
}

.entity-table :deep(tbody tr:last-child td) {
  border-bottom: 0;
}

.entity-table :deep(tbody tr:hover) {
  transform: translateY(-1px);
  box-shadow: inset 0 0 0 1px rgba(108, 186, 228, 0.24);
}

.table-skeleton {
  border: 1px solid rgba(99, 173, 219, 0.18);
  border-radius: 16px;
  overflow: hidden;
  background: linear-gradient(180deg, rgba(8, 14, 22, 0.9), rgba(6, 11, 18, 0.82));
  position: relative;
  box-shadow: inset 0 1px 0 rgba(132, 205, 241, 0.06);
}

.table-skeleton::before {
  content: "";
  position: absolute;
  inset: 0;
  background-image: linear-gradient(rgba(126, 177, 217, 0.05) 1px, transparent 1px),
    linear-gradient(90deg, rgba(126, 177, 217, 0.04) 1px, transparent 1px);
  background-size: 28px 28px;
  opacity: 0.22;
  pointer-events: none;
}

.table-skeleton::after {
  content: "";
  position: absolute;
  inset: 0;
  background: linear-gradient(
    112deg,
    rgba(24, 40, 58, 0) 0%,
    rgba(86, 166, 212, 0.06) 32%,
    rgba(136, 229, 255, 0.18) 50%,
    rgba(24, 40, 58, 0) 86%
  );
  animation: table-skeleton-sweep 1.5s linear infinite;
  pointer-events: none;
}

.table-skeleton__head,
.table-skeleton__row {
  display: grid;
  position: relative;
  z-index: 1;
}

.table-skeleton__head {
  gap: 12px;
  padding: 14px;
  border-bottom: 1px solid rgba(99, 173, 219, 0.14);
  background: linear-gradient(180deg, rgba(11, 19, 30, 0.95), rgba(8, 14, 23, 0.82));
}

.table-skeleton__head-cell,
.table-skeleton__cell {
  display: block;
  height: 12px;
  border-radius: 999px;
  background: linear-gradient(
    90deg,
    rgba(58, 108, 152, 0.28) 0%,
    rgba(128, 214, 248, 0.42) 50%,
    rgba(58, 108, 152, 0.28) 100%
  );
  background-size: 220% 100%;
  animation: table-skeleton-slide 1.25s ease-in-out infinite;
  box-shadow: inset 0 0 0 1px rgba(129, 190, 227, 0.06);
}

.table-skeleton__head-cell {
  width: 68%;
  height: 10px;
}

.table-skeleton__row {
  gap: 12px;
  padding: 14px;
  border-bottom: 1px solid rgba(99, 173, 219, 0.1);
  background: linear-gradient(180deg, rgba(11, 19, 30, 0.2), rgba(7, 12, 20, 0.42));
}

.table-skeleton__row:last-child {
  border-bottom: 0;
}

.table-skeleton__row:nth-child(odd) {
  background: linear-gradient(180deg, rgba(12, 21, 33, 0.34), rgba(7, 12, 20, 0.46));
}

@keyframes table-skeleton-slide {
  0% {
    background-position: 120% 0;
  }
  100% {
    background-position: -120% 0;
  }
}

@keyframes table-skeleton-sweep {
  from {
    transform: translateX(-100%);
  }
  to {
    transform: translateX(100%);
  }
}
</style>
