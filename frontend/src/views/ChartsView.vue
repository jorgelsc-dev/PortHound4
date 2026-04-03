<template>
  <div>
    <ViewHeader
      overline="Visual Intelligence"
      title="Charts Lab"
      description="D3-powered analytics across targets, ports, banners, tags and timelines."
      :refresh-loading="loading"
      @refresh="load"
    />

    <v-alert v-if="error" type="error" variant="tonal" class="my-4">
      {{ error }}
    </v-alert>
    <v-alert v-if="d3Error" type="warning" variant="tonal" class="mb-4">
      {{ d3Error }}
    </v-alert>

    <v-row dense class="mb-4">
      <v-col
        v-for="card in summaryCards"
        :key="card.label"
        cols="12"
        sm="6"
        md="3"
        lg="2"
      >
        <v-card variant="tonal" class="summary-card pa-4">
          <div class="text-caption text-medium-emphasis">{{ card.label }}</div>
          <div class="text-h5 font-weight-bold mt-1">{{ card.value }}</div>
        </v-card>
      </v-col>
    </v-row>

    <v-row dense>
      <v-col cols="12" md="6" lg="4">
        <DataPanel
          title="Ports by Protocol"
          subtitle="Distribution across tcp/udp/icmp/sctp."
          :loading="loading"
          :last-updated="lastUpdated"
          :show-refresh="false"
          class="chart-panel"
        >
          <svg ref="portsByProtoSvg" class="chart-svg chart-svg--donut" />
        </DataPanel>
      </v-col>
      <v-col cols="12" md="6" lg="4">
        <DataPanel
          title="Targets by Status"
          subtitle="Active, stopped, restarting."
          :loading="loading"
          :last-updated="lastUpdated"
          :show-refresh="false"
          class="chart-panel"
        >
          <svg ref="targetsStatusSvg" class="chart-svg chart-svg--donut" />
        </DataPanel>
      </v-col>
      <v-col cols="12" md="12" lg="4">
        <DataPanel
          title="Target Progress Buckets"
          subtitle="Scan completion distribution."
          :loading="loading"
          :last-updated="lastUpdated"
          :show-refresh="false"
          class="chart-panel"
        >
          <svg ref="targetProgressSvg" class="chart-svg" />
        </DataPanel>
      </v-col>
    </v-row>

    <v-row dense class="mt-1">
      <v-col cols="12" md="6">
        <DataPanel
          title="Ports State by Protocol"
          subtitle="Open vs filtered vs other."
          :loading="loading"
          :last-updated="lastUpdated"
          :show-refresh="false"
          class="chart-panel"
        >
          <svg ref="portsStateSvg" class="chart-svg" />
        </DataPanel>
      </v-col>
      <v-col cols="12" md="6">
        <DataPanel
          title="Discovery Timeline"
          subtitle="Daily targets, ports and banners."
          :loading="loading"
          :last-updated="lastUpdated"
          :show-refresh="false"
          class="chart-panel"
        >
          <svg ref="timelineSvg" class="chart-svg" />
        </DataPanel>
      </v-col>
    </v-row>

    <v-row dense class="mt-1">
      <v-col cols="12" md="6">
        <DataPanel
          title="Top Open Ports"
          subtitle="Most frequent open services."
          :loading="loading"
          :last-updated="lastUpdated"
          :show-refresh="false"
          class="chart-panel"
        >
          <svg ref="topPortsSvg" class="chart-svg" />
        </DataPanel>
      </v-col>
      <v-col cols="12" md="6">
        <DataPanel
          title="Top Exposed Hosts"
          subtitle="Hosts with highest open-port counts."
          :loading="loading"
          :last-updated="lastUpdated"
          :show-refresh="false"
          class="chart-panel"
        >
          <svg ref="topHostsSvg" class="chart-svg" />
        </DataPanel>
      </v-col>
    </v-row>

    <v-row dense class="mt-1">
      <v-col cols="12" md="6">
        <DataPanel
          title="Banner Length Buckets"
          subtitle="Response size profile."
          :loading="loading"
          :last-updated="lastUpdated"
          :show-refresh="false"
          class="chart-panel"
        >
          <svg ref="bannerLengthSvg" class="chart-svg" />
        </DataPanel>
      </v-col>
      <v-col cols="12" md="6">
        <DataPanel
          title="Risk Port Exposure"
          subtitle="Commonly abused open ports."
          :loading="loading"
          :last-updated="lastUpdated"
          :show-refresh="false"
          class="chart-panel"
        >
          <svg ref="riskPortsSvg" class="chart-svg" />
        </DataPanel>
      </v-col>
    </v-row>

    <v-row dense class="mt-1">
      <v-col cols="12" md="6">
        <DataPanel
          title="Top Tag Keys"
          subtitle="Metadata density by tag key."
          :loading="loading"
          :last-updated="lastUpdated"
          :show-refresh="false"
          class="chart-panel"
        >
          <svg ref="topTagKeysSvg" class="chart-svg" />
        </DataPanel>
      </v-col>
      <v-col cols="12" md="6">
        <DataPanel
          title="Top Service Signatures"
          subtitle="Most repeated service/product values."
          :loading="loading"
          :last-updated="lastUpdated"
          :show-refresh="false"
          class="chart-panel"
        >
          <svg ref="serviceSignaturesSvg" class="chart-svg" />
        </DataPanel>
      </v-col>
    </v-row>
  </div>
</template>

<script>
import store from "../state/appStore";
import ViewHeader from "../components/ui/ViewHeader.vue";
import DataPanel from "../components/ui/DataPanel.vue";
import { loadD3FromCdn } from "../utils/d3Loader";

const CHART_COLORS = [
  "#4cc9f0",
  "#4895ef",
  "#4361ee",
  "#3f37c9",
  "#2ec4b6",
  "#06d6a0",
  "#f4a261",
  "#e76f51",
  "#ff9f1c",
  "#90be6d",
  "#43aa8b",
  "#577590",
];

function emptyAnalytics() {
  return {
    generated_at: "",
    summary: {},
    ports_by_proto: [],
    ports_state_by_proto: [],
    top_open_ports: [],
    top_ips_by_open_ports: [],
    risk_ports: [],
    targets_by_status: [],
    target_progress_buckets: [],
    banner_length_buckets: [],
    top_tag_keys: [],
    top_service_signatures: [],
    timeline: [],
  };
}

export default {
  name: "ChartsView",
  components: {
    ViewHeader,
    DataPanel,
  },
  data() {
    return {
      store,
      loading: false,
      error: "",
      d3Error: "",
      lastUpdated: "n/a",
      analytics: emptyAnalytics(),
      d3: null,
      resizeTimer: null,
    };
  },
  computed: {
    summaryCards() {
      const summary = this.analytics.summary || {};
      const labelMap = [
        ["Targets", summary.targets || 0],
        ["Ports", summary.ports || 0],
        ["Open Ports", summary.open_ports || 0],
        ["Filtered Ports", summary.filtered_ports || 0],
        ["Banners", summary.banners || 0],
        ["Tags", summary.tags || 0],
        ["Favicons", summary.favicons || 0],
        ["Unique Hosts", summary.unique_hosts || 0],
      ];
      return labelMap.map(([label, rawValue]) => ({
        label,
        value: this.formatNumber(rawValue),
      }));
    },
  },
  mounted() {
    this.load();
    window.addEventListener("resize", this.onResize, { passive: true });
  },
  beforeUnmount() {
    if (this.resizeTimer) {
      clearTimeout(this.resizeTimer);
      this.resizeTimer = null;
    }
    window.removeEventListener("resize", this.onResize);
  },
  methods: {
    formatNumber(value) {
      try {
        return new Intl.NumberFormat().format(Number(value || 0));
      } catch (err) {
        return String(value || 0);
      }
    },
    async ensureD3() {
      if (this.d3) return this.d3;
      this.d3 = await loadD3FromCdn();
      return this.d3;
    },
    async load() {
      this.loading = true;
      this.error = "";
      this.d3Error = "";
      try {
        const payload = await this.store.fetchJson("/api/charts/analytics");
        this.analytics = payload && typeof payload === "object" ? payload : emptyAnalytics();
        this.lastUpdated = this.analytics.generated_at || new Date().toISOString();
        try {
          await this.ensureD3();
        } catch (err) {
          this.d3Error = `D3 unavailable: ${String(err || "")}`;
        }
        this.$nextTick(() => this.renderAllCharts());
      } catch (err) {
        this.error = String(err || "Failed to load chart analytics");
      } finally {
        this.loading = false;
      }
    },
    onResize() {
      if (this.resizeTimer) clearTimeout(this.resizeTimer);
      this.resizeTimer = setTimeout(() => {
        this.resizeTimer = null;
        this.renderAllCharts();
      }, 160);
    },
    renderAllCharts() {
      if (!this.d3) return;
      this.renderDonut("portsByProtoSvg", this.analytics.ports_by_proto, "Protocols");
      this.renderDonut("targetsStatusSvg", this.analytics.targets_by_status, "Status");
      this.renderVerticalBars(
        "targetProgressSvg",
        this.analytics.target_progress_buckets,
        "#06d6a0",
      );
      this.renderStackedBars("portsStateSvg", this.analytics.ports_state_by_proto);
      this.renderTimeline("timelineSvg", this.analytics.timeline);
      this.renderHorizontalBars("topPortsSvg", this.analytics.top_open_ports, "#4cc9f0");
      this.renderHorizontalBars(
        "topHostsSvg",
        this.analytics.top_ips_by_open_ports,
        "#4895ef",
      );
      this.renderVerticalBars(
        "bannerLengthSvg",
        this.analytics.banner_length_buckets,
        "#f4a261",
      );
      this.renderHorizontalBars("riskPortsSvg", this.analytics.risk_ports, "#ef476f");
      this.renderHorizontalBars("topTagKeysSvg", this.analytics.top_tag_keys, "#43aa8b");
      this.renderHorizontalBars(
        "serviceSignaturesSvg",
        this.analytics.top_service_signatures,
        "#577590",
      );
    },
    resolveFrame(refName, minHeight = 260) {
      const element = this.$refs[refName];
      if (!element || !this.d3) return null;
      const widthRaw = element.clientWidth || element.getBoundingClientRect().width || 320;
      const heightRaw = element.clientHeight || minHeight;
      const width = Math.max(320, Math.floor(widthRaw));
      const height = Math.max(minHeight, Math.floor(heightRaw));
      const svg = this.d3.select(element);
      svg.selectAll("*").remove();
      svg
        .attr("viewBox", `0 0 ${width} ${height}`)
        .attr("preserveAspectRatio", "xMidYMid meet");
      return { svg, width, height };
    },
    renderNoData(svg, width, height, message = "No data") {
      svg
        .append("text")
        .attr("x", width / 2)
        .attr("y", height / 2)
        .attr("text-anchor", "middle")
        .attr("fill", "#8da9c4")
        .style("font-size", "13px")
        .text(message);
    },
    renderDonut(refName, rawSeries, centerLabel = "") {
      const frame = this.resolveFrame(refName, 280);
      if (!frame) return;
      const { svg, width, height } = frame;
      const series = Array.isArray(rawSeries)
        ? rawSeries.filter((item) => Number((item || {}).value || 0) > 0)
        : [];
      if (!series.length) {
        this.renderNoData(svg, width, height);
        return;
      }

      const radius = Math.min(width, height) * 0.28;
      const centerX = width * 0.38;
      const centerY = height * 0.52;
      const color = this.d3
        .scaleOrdinal()
        .domain(series.map((item) => String(item.label || "")))
        .range(CHART_COLORS);
      const pie = this.d3
        .pie()
        .sort(null)
        .value((item) => Number(item.value || 0));
      const arc = this.d3.arc().innerRadius(radius * 0.57).outerRadius(radius);
      const total = this.d3.sum(series, (item) => Number(item.value || 0));

      const group = svg
        .append("g")
        .attr("transform", `translate(${centerX}, ${centerY})`);
      group
        .selectAll("path")
        .data(pie(series))
        .enter()
        .append("path")
        .attr("fill", (item) => color(String(item.data.label || "")))
        .attr("stroke", "#0b1220")
        .attr("stroke-width", 1.2)
        .attr("d", arc);

      group
        .append("text")
        .attr("text-anchor", "middle")
        .attr("dy", "-0.2em")
        .attr("fill", "#e2f1ff")
        .style("font-size", "17px")
        .style("font-weight", "700")
        .text(this.formatNumber(total));
      group
        .append("text")
        .attr("text-anchor", "middle")
        .attr("dy", "1.2em")
        .attr("fill", "#8da9c4")
        .style("font-size", "12px")
        .text(centerLabel);

      const legend = svg
        .append("g")
        .attr("transform", `translate(${Math.max(width * 0.62, 220)}, 34)`);
      series.slice(0, 8).forEach((row, index) => {
        const y = index * 24;
        legend
          .append("rect")
          .attr("x", 0)
          .attr("y", y)
          .attr("width", 11)
          .attr("height", 11)
          .attr("rx", 2)
          .attr("fill", color(String(row.label || "")));
        legend
          .append("text")
          .attr("x", 18)
          .attr("y", y + 10)
          .attr("fill", "#bdd3eb")
          .style("font-size", "12px")
          .text(`${row.label}: ${this.formatNumber(row.value)}`);
      });
    },
    renderHorizontalBars(refName, rawSeries, color = "#4cc9f0") {
      const frame = this.resolveFrame(refName, 300);
      if (!frame) return;
      const { svg, width, height } = frame;
      const series = Array.isArray(rawSeries)
        ? rawSeries.filter((item) => Number((item || {}).value || 0) > 0).slice(0, 10)
        : [];
      if (!series.length) {
        this.renderNoData(svg, width, height);
        return;
      }

      const margin = { top: 18, right: 54, bottom: 20, left: 126 };
      const chartWidth = width - margin.left - margin.right;
      const chartHeight = height - margin.top - margin.bottom;
      const group = svg
        .append("g")
        .attr("transform", `translate(${margin.left},${margin.top})`);

      const x = this.d3
        .scaleLinear()
        .domain([0, this.d3.max(series, (item) => Number(item.value || 0)) || 1])
        .nice()
        .range([0, chartWidth]);
      const y = this.d3
        .scaleBand()
        .domain(series.map((item) => String(item.label || "")))
        .range([0, chartHeight])
        .padding(0.22);

      group
        .append("g")
        .attr("class", "grid")
        .call(this.d3.axisBottom(x).ticks(5).tickSize(chartHeight).tickFormat(""))
        .selectAll("line")
        .attr("stroke", "rgba(125, 178, 214, 0.2)");

      group
        .select(".grid")
        .attr("transform", "translate(0,0)")
        .select(".domain")
        .remove();

      group
        .selectAll("rect.bar")
        .data(series)
        .enter()
        .append("rect")
        .attr("class", "bar")
        .attr("x", 0)
        .attr("y", (item) => y(String(item.label || "")))
        .attr("width", (item) => x(Number(item.value || 0)))
        .attr("height", y.bandwidth())
        .attr("rx", 4)
        .attr("fill", color)
        .attr("opacity", 0.9);

      group
        .append("g")
        .call(
          this.d3
            .axisLeft(y)
            .tickSize(0)
            .tickFormat((value) => {
              const label = String(value || "");
              return label.length > 16 ? `${label.slice(0, 14)}...` : label;
            }),
        )
        .selectAll("text")
        .attr("fill", "#bad1e8")
        .style("font-size", "11px");

      group.selectAll(".domain").remove();

      group
        .selectAll("text.value")
        .data(series)
        .enter()
        .append("text")
        .attr("x", (item) => x(Number(item.value || 0)) + 6)
        .attr("y", (item) => (y(String(item.label || "")) || 0) + y.bandwidth() * 0.7)
        .attr("fill", "#d7e8f7")
        .style("font-size", "11px")
        .text((item) => this.formatNumber(item.value));
    },
    renderVerticalBars(refName, rawSeries, color = "#06d6a0") {
      const frame = this.resolveFrame(refName, 300);
      if (!frame) return;
      const { svg, width, height } = frame;
      const series = Array.isArray(rawSeries)
        ? rawSeries.filter((item) => Number((item || {}).value || 0) > 0)
        : [];
      if (!series.length) {
        this.renderNoData(svg, width, height);
        return;
      }

      const margin = { top: 20, right: 20, bottom: 46, left: 45 };
      const chartWidth = width - margin.left - margin.right;
      const chartHeight = height - margin.top - margin.bottom;
      const group = svg
        .append("g")
        .attr("transform", `translate(${margin.left},${margin.top})`);

      const x = this.d3
        .scaleBand()
        .domain(series.map((item) => String(item.label || "")))
        .range([0, chartWidth])
        .padding(0.25);
      const y = this.d3
        .scaleLinear()
        .domain([0, this.d3.max(series, (item) => Number(item.value || 0)) || 1])
        .nice()
        .range([chartHeight, 0]);

      group
        .append("g")
        .call(this.d3.axisLeft(y).ticks(5))
        .selectAll("text")
        .attr("fill", "#a8c4df")
        .style("font-size", "11px");
      group.selectAll(".domain").attr("stroke", "rgba(127, 173, 208, 0.4)");
      group.selectAll(".tick line").attr("stroke", "rgba(127, 173, 208, 0.2)");

      group
        .append("g")
        .attr("transform", `translate(0,${chartHeight})`)
        .call(this.d3.axisBottom(x))
        .selectAll("text")
        .attr("fill", "#bad1e8")
        .style("font-size", "11px")
        .attr("transform", "rotate(-28)")
        .style("text-anchor", "end");

      group
        .selectAll("rect.bar")
        .data(series)
        .enter()
        .append("rect")
        .attr("x", (item) => x(String(item.label || "")))
        .attr("y", (item) => y(Number(item.value || 0)))
        .attr("width", x.bandwidth())
        .attr("height", (item) => chartHeight - y(Number(item.value || 0)))
        .attr("rx", 4)
        .attr("fill", color)
        .attr("opacity", 0.9);
    },
    renderStackedBars(refName, rawSeries) {
      const frame = this.resolveFrame(refName, 300);
      if (!frame) return;
      const { svg, width, height } = frame;
      const series = Array.isArray(rawSeries)
        ? rawSeries.filter((item) => item && item.proto)
        : [];
      if (!series.length) {
        this.renderNoData(svg, width, height);
        return;
      }

      const margin = { top: 22, right: 22, bottom: 44, left: 48 };
      const chartWidth = width - margin.left - margin.right;
      const chartHeight = height - margin.top - margin.bottom;
      const group = svg
        .append("g")
        .attr("transform", `translate(${margin.left},${margin.top})`);

      const keys = ["open", "filtered", "other"];
      const color = this.d3
        .scaleOrdinal()
        .domain(keys)
        .range(["#06d6a0", "#f4a261", "#577590"]);
      const stack = this.d3.stack().keys(keys);
      const stacked = stack(series);

      const x = this.d3
        .scaleBand()
        .domain(series.map((item) => String(item.proto || "")))
        .range([0, chartWidth])
        .padding(0.28);
      const y = this.d3
        .scaleLinear()
        .domain([
          0,
          this.d3.max(series, (item) => Number(item.open || 0) + Number(item.filtered || 0) + Number(item.other || 0)) || 1,
        ])
        .nice()
        .range([chartHeight, 0]);

      group
        .append("g")
        .call(this.d3.axisLeft(y).ticks(5))
        .selectAll("text")
        .attr("fill", "#a8c4df")
        .style("font-size", "11px");
      group.selectAll(".tick line").attr("stroke", "rgba(127, 173, 208, 0.2)");
      group.selectAll(".domain").attr("stroke", "rgba(127, 173, 208, 0.4)");

      group
        .append("g")
        .attr("transform", `translate(0,${chartHeight})`)
        .call(this.d3.axisBottom(x))
        .selectAll("text")
        .attr("fill", "#bad1e8")
        .style("font-size", "11px");

      group
        .selectAll("g.layer")
        .data(stacked)
        .enter()
        .append("g")
        .attr("fill", (layer) => color(layer.key))
        .selectAll("rect")
        .data((layer) => layer)
        .enter()
        .append("rect")
        .attr("x", (item) => x(String((item.data || {}).proto || "")))
        .attr("y", (item) => y(item[1]))
        .attr("height", (item) => y(item[0]) - y(item[1]))
        .attr("width", x.bandwidth())
        .attr("opacity", 0.9);

      const legend = svg.append("g").attr("transform", `translate(${width - 200}, 12)`);
      keys.forEach((key, index) => {
        legend
          .append("rect")
          .attr("x", index * 62)
          .attr("y", 0)
          .attr("width", 10)
          .attr("height", 10)
          .attr("rx", 2)
          .attr("fill", color(key));
        legend
          .append("text")
          .attr("x", index * 62 + 14)
          .attr("y", 9)
          .attr("fill", "#c4d8eb")
          .style("font-size", "11px")
          .text(key);
      });
    },
    renderTimeline(refName, rawSeries) {
      const frame = this.resolveFrame(refName, 300);
      if (!frame) return;
      const { svg, width, height } = frame;
      const series = Array.isArray(rawSeries) ? rawSeries.filter((item) => item && item.day) : [];
      if (!series.length) {
        this.renderNoData(svg, width, height, "No timeline data");
        return;
      }

      const margin = { top: 24, right: 20, bottom: 46, left: 46 };
      const chartWidth = width - margin.left - margin.right;
      const chartHeight = height - margin.top - margin.bottom;
      const group = svg
        .append("g")
        .attr("transform", `translate(${margin.left},${margin.top})`);
      const x = this.d3
        .scalePoint()
        .domain(series.map((item) => String(item.day || "")))
        .range([0, chartWidth])
        .padding(0.35);
      const y = this.d3
        .scaleLinear()
        .domain([
          0,
          this.d3.max(series, (item) =>
            Math.max(
              Number(item.ports || 0),
              Number(item.banners || 0),
              Number(item.targets || 0),
            ),
          ) || 1,
        ])
        .nice()
        .range([chartHeight, 0]);

      group
        .append("g")
        .call(this.d3.axisLeft(y).ticks(5))
        .selectAll("text")
        .attr("fill", "#a8c4df")
        .style("font-size", "11px");
      group.selectAll(".tick line").attr("stroke", "rgba(127, 173, 208, 0.2)");
      group.selectAll(".domain").attr("stroke", "rgba(127, 173, 208, 0.4)");

      group
        .append("g")
        .attr("transform", `translate(0,${chartHeight})`)
        .call(
          this.d3.axisBottom(x).tickFormat((day) => {
            const label = String(day || "");
            return label.length > 5 ? label.slice(5) : label;
          }),
        )
        .selectAll("text")
        .attr("fill", "#bad1e8")
        .style("font-size", "10px")
        .attr("transform", "rotate(-32)")
        .style("text-anchor", "end");

      const defs = [
        { key: "targets", label: "targets", color: "#4cc9f0" },
        { key: "ports", label: "ports", color: "#06d6a0" },
        { key: "banners", label: "banners", color: "#f4a261" },
      ];

      defs.forEach((lineDef) => {
        const line = this.d3
          .line()
          .x((item) => x(String(item.day || "")))
          .y((item) => y(Number(item[lineDef.key] || 0)))
          .curve(this.d3.curveMonotoneX);

        group
          .append("path")
          .datum(series)
          .attr("fill", "none")
          .attr("stroke", lineDef.color)
          .attr("stroke-width", 2.2)
          .attr("d", line);

        group
          .selectAll(`circle.${lineDef.key}`)
          .data(series)
          .enter()
          .append("circle")
          .attr("class", lineDef.key)
          .attr("cx", (item) => x(String(item.day || "")))
          .attr("cy", (item) => y(Number(item[lineDef.key] || 0)))
          .attr("r", 2.6)
          .attr("fill", lineDef.color);
      });

      const legend = svg.append("g").attr("transform", `translate(${width - 210}, 8)`);
      defs.forEach((item, index) => {
        const xOffset = index * 66;
        legend
          .append("rect")
          .attr("x", xOffset)
          .attr("y", 0)
          .attr("width", 10)
          .attr("height", 10)
          .attr("rx", 2)
          .attr("fill", item.color);
        legend
          .append("text")
          .attr("x", xOffset + 14)
          .attr("y", 9)
          .attr("fill", "#c4d8eb")
          .style("font-size", "11px")
          .text(item.label);
      });
    },
  },
};
</script>

<style scoped>
.summary-card {
  border-radius: 16px;
}

.chart-panel {
  min-height: 350px;
}

.chart-svg {
  width: 100%;
  height: 300px;
  display: block;
}

.chart-svg--donut {
  height: 312px;
}
</style>
