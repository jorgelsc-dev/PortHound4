<template>
  <DataPanel
    :title="panelTitle"
    :subtitle="panelSubtitle"
    :loading="loading"
    :error="error"
    :last-updated="lastUpdated"
    :show-refresh="showRefresh"
    :show-header="showPanelHeader"
    :keep-content-on-loading="true"
    @refresh="manualRefresh"
  >
    <template #skeleton>
      <v-skeleton-loader type="image, table-thead, table-row@4" class="skeleton-block" />
    </template>

    <div v-if="showIntro" class="map-intro">
      <div class="map-intro__eyebrow">Live telemetry viewport</div>
      <div class="map-intro__title">{{ isGlobeMode ? "Orbital Scan Globe" : "Live Scan Map" }}</div>
      <div class="map-intro__description">
        {{
          isGlobeMode
            ? "Orthographic globe with auto-rotation, front-hemisphere clustering, and animated route traces."
            : "Only public IPs render inside the map. Origin and private ranges stay outside the map frame."
        }}
      </div>
      <div v-if="statusInfoText || geoipInfoText" class="map-intro__meta">
        <span v-if="statusInfoText">{{ statusInfoText }}</span>
        <span
          v-if="statusInfoText && geoipInfoText"
          class="map-intro__meta-divider"
          aria-hidden="true"
        ></span>
        <span v-if="geoipInfoText">{{ geoipInfoText }}</span>
      </div>
    </div>

    <div
      class="map-wrapper"
      :class="[
        showIntro ? 'mt-4' : '',
        { 'map-wrapper--immersive': immersive, 'map-wrapper--globe': isGlobeMode },
      ]"
    >
      <div v-if="showProjectionSwitch || immersive" class="map-overlay">
        <div v-if="showProjectionSwitch" class="map-overlay__group">
          <div class="map-overlay__label">Projection</div>
          <v-btn-toggle
            v-model="projectionMode"
            mandatory
            density="comfortable"
            color="primary"
            variant="outlined"
            class="map-projection-toggle"
          >
            <v-btn value="flat" size="small">Flat</v-btn>
            <v-btn value="globe" size="small">Globe</v-btn>
          </v-btn-toggle>
        </div>

        <div class="map-overlay__meta">
          <v-btn
            v-if="showRefresh && !showPanelHeader"
            size="small"
            variant="outlined"
            color="primary"
            prepend-icon="mdi-refresh"
            :loading="loading"
            class="map-refresh-btn"
            @click="manualRefresh"
          >
            Refresh
          </v-btn>
          <span class="map-status-pill">{{ projectionLabel }}</span>
          <span class="map-status-pill">{{ wsLabel }}</span>
          <span v-if="geoipSourceLabel" class="map-status-pill map-status-pill--accent">
            {{ geoipSourceLabel }}
          </span>
        </div>
      </div>

      <svg
        :viewBox="`0 0 ${mapWidth} ${mapHeight}`"
        role="img"
        aria-label="PortHound geolocated scan map"
      >
        <defs>
          <radialGradient :id="oceanGradientId" cx="50%" cy="48%" r="72%">
            <stop offset="0%" stop-color="rgba(24, 92, 143, 0.96)" />
            <stop offset="48%" stop-color="rgba(10, 41, 73, 0.98)" />
            <stop offset="100%" stop-color="rgba(3, 16, 30, 1)" />
          </radialGradient>
          <radialGradient :id="globeOceanGradientId" cx="34%" cy="28%" r="82%">
            <stop offset="0%" stop-color="rgba(43, 167, 255, 0.96)" />
            <stop offset="42%" stop-color="rgba(12, 61, 117, 0.98)" />
            <stop offset="100%" stop-color="rgba(2, 16, 32, 1)" />
          </radialGradient>
          <radialGradient :id="globeAtmosphereGradientId" cx="50%" cy="50%" r="70%">
            <stop offset="64%" stop-color="rgba(94, 227, 255, 0)" />
            <stop offset="84%" stop-color="rgba(94, 227, 255, 0.16)" />
            <stop offset="100%" stop-color="rgba(94, 227, 255, 0.02)" />
          </radialGradient>
          <linearGradient :id="landGradientId" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stop-color="rgba(102, 255, 210, 0.28)" />
            <stop offset="55%" stop-color="rgba(76, 175, 228, 0.18)" />
            <stop offset="100%" stop-color="rgba(48, 102, 160, 0.22)" />
          </linearGradient>
          <linearGradient :id="frameGradientId" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stop-color="rgba(85, 219, 255, 0.18)" />
            <stop offset="50%" stop-color="rgba(94, 248, 190, 0.6)" />
            <stop offset="100%" stop-color="rgba(255, 172, 78, 0.18)" />
          </linearGradient>
          <filter :id="arcGlowFilterId" x="-30%" y="-30%" width="160%" height="160%">
            <feGaussianBlur stdDeviation="3.4" result="blurred" />
            <feMerge>
              <feMergeNode in="blurred" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
          <filter :id="pointGlowFilterId" x="-80%" y="-80%" width="260%" height="260%">
            <feGaussianBlur stdDeviation="4.2" result="pointBlur" />
            <feMerge>
              <feMergeNode in="pointBlur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
          <clipPath :id="globeClipId">
            <circle :cx="globeCenterX" :cy="globeCenterY" :r="globeRadius" />
          </clipPath>
        </defs>

        <rect
          x="0"
          y="0"
          :width="mapWidth"
          :height="mapHeight"
          fill="rgba(4, 10, 18, 0.94)"
        />

        <template v-if="!isGlobeMode">
          <rect
            :x="mapPadding"
            :y="mapPadding"
            :width="mapWidth - (mapPadding * 2)"
            :height="mapHeight - (mapPadding * 2)"
            :fill="`url(#${oceanGradientId})`"
            stroke="rgba(73, 165, 210, 0.24)"
            stroke-width="0.9"
            rx="14"
          />
          <rect
            :x="mapPadding + 6"
            :y="mapPadding + 6"
            :width="mapWidth - (mapPadding * 2) - 12"
            :height="mapHeight - (mapPadding * 2) - 12"
            fill="none"
            :stroke="`url(#${frameGradientId})`"
            stroke-width="1"
            rx="12"
            opacity="0.72"
          />
          <circle
            :cx="mapWidth * 0.18"
            :cy="mapHeight * 0.32"
            :r="mapWidth * 0.24"
            fill="rgba(60, 171, 255, 0.12)"
          />
          <circle
            :cx="mapWidth * 0.74"
            :cy="mapHeight * 0.24"
            :r="mapWidth * 0.18"
            fill="rgba(66, 238, 189, 0.08)"
          />
        </template>

        <template v-else>
          <ellipse
            :cx="globeCenterX"
            :cy="globeCenterY + (globeRadius * 0.92)"
            :rx="globeRadius * 0.9"
            :ry="globeRadius * 0.18"
            fill="rgba(10, 18, 28, 0.82)"
            opacity="0.82"
          />
          <circle
            :cx="globeCenterX"
            :cy="globeCenterY"
            :r="globeRadius + 22"
            :fill="`url(#${globeAtmosphereGradientId})`"
            opacity="0.9"
          />
          <circle
            :cx="globeCenterX"
            :cy="globeCenterY"
            :r="globeRadius"
            :fill="`url(#${globeOceanGradientId})`"
            stroke="rgba(111, 216, 255, 0.34)"
            stroke-width="1.1"
          />
          <g :clip-path="`url(#${globeClipId})`">
            <ellipse
              :cx="globeCenterX + (globeRadius * 0.24)"
              :cy="globeCenterY + (globeRadius * 0.08)"
              :rx="globeRadius * 0.86"
              :ry="globeRadius * 0.96"
              fill="rgba(1, 8, 18, 0.34)"
            />
            <ellipse
              :cx="globeCenterX - (globeRadius * 0.28)"
              :cy="globeCenterY - (globeRadius * 0.36)"
              :rx="globeRadius * 0.5"
              :ry="globeRadius * 0.34"
              fill="rgba(146, 245, 255, 0.1)"
            />
            <g class="map-graticule">
              <path
                v-for="path in globeLatitudePaths"
                :key="path.id"
                :d="path.d"
                fill="none"
                stroke="rgba(110, 192, 240, 0.14)"
                stroke-width="0.7"
              />
              <path
                v-for="path in globeLongitudePaths"
                :key="path.id"
                :d="path.d"
                fill="none"
                stroke="rgba(110, 192, 240, 0.12)"
                stroke-width="0.7"
              />
            </g>
          </g>
        </template>

        <g v-if="!isGlobeMode" class="map-land">
          <path
            v-for="shape in worldPaths"
            :key="shape.id"
            :d="shape.d"
            :fill="`url(#${landGradientId})`"
            stroke="rgba(143, 231, 202, 0.24)"
            stroke-width="0.9"
          />
        </g>

        <g v-if="!isGlobeMode" class="map-graticule">
          <line
            v-for="lat in graticuleLatitudes"
            :key="`lat-${lat}`"
            :x1="mapPadding"
            :y1="latitudeToY(lat)"
            :x2="mapWidth - mapPadding"
            :y2="latitudeToY(lat)"
            stroke="rgba(110, 192, 240, 0.18)"
            stroke-width="0.6"
          />
          <line
            v-for="lon in graticuleLongitudes"
            :key="`lon-${lon}`"
            :x1="longitudeToX(lon)"
            :y1="mapPadding"
            :x2="longitudeToX(lon)"
            :y2="mapHeight - mapPadding"
            stroke="rgba(110, 192, 240, 0.12)"
            stroke-width="0.6"
          />
        </g>

        <g v-if="isGlobeMode" :clip-path="`url(#${globeClipId})`" class="map-land map-land--globe">
          <path
            v-for="shape in worldPaths"
            :key="shape.id"
            :d="shape.d"
            :fill="`url(#${landGradientId})`"
            stroke="rgba(143, 231, 202, 0.22)"
            stroke-width="0.8"
            opacity="0.96"
          />
        </g>

        <g class="map-arcs">
          <path
            v-for="arc in arcPaths"
            :key="`glow-${arc.id}`"
            :d="arc.d"
            fill="none"
            :stroke="arc.glow"
            :stroke-width="arc.strokeWidth + 2.8"
            stroke-linecap="round"
            opacity="0.2"
            :filter="`url(#${arcGlowFilterId})`"
          />
          <path
            v-for="arc in arcPaths"
            :key="arc.id"
            :d="arc.d"
            fill="none"
            :stroke="arc.stroke"
            :stroke-width="arc.strokeWidth"
            stroke-linecap="round"
            class="map-arc-flow"
            :style="arc.style"
          />
          <circle
            v-for="arc in arcPaths"
            :key="`trace-${arc.id}`"
            :r="arc.traceRadius"
            :fill="arc.traceColor"
            class="map-arc-trace"
            :filter="`url(#${pointGlowFilterId})`"
          >
            <animateMotion :dur="arc.duration" :begin="arc.begin" repeatCount="indefinite" :path="arc.d" />
          </circle>
        </g>

        <g v-if="!isGlobeMode" class="map-points">
          <circle
            v-for="point in projectedPublicPoints"
            :key="`glow-${point.id}`"
            :cx="point.x"
            :cy="point.y"
            :r="point.radius * 3.4"
            :fill="point.glowColor"
            opacity="0.24"
            :filter="`url(#${pointGlowFilterId})`"
          />
          <circle
            v-for="point in projectedPublicPoints"
            :key="`ring-${point.id}`"
            :cx="point.x"
            :cy="point.y"
            :r="point.radius * 1.9"
            fill="none"
            :stroke="point.ringColor"
            stroke-width="0.9"
            opacity="0.72"
          />
          <circle
            v-for="point in projectedPublicPoints"
            :key="point.id"
            :cx="point.x"
            :cy="point.y"
            :r="point.radius"
            :fill="point.color"
            stroke="rgba(229, 247, 255, 0.8)"
            stroke-width="0.7"
          />
        </g>

        <g v-else :clip-path="`url(#${globeClipId})`" class="map-points map-points--globe">
          <circle
            v-for="point in projectedPublicPoints"
            :key="`glow-${point.id}`"
            :cx="point.x"
            :cy="point.y"
            :r="point.radius * 4.1"
            :fill="point.glowColor"
            opacity="0.24"
            :filter="`url(#${pointGlowFilterId})`"
          />
          <circle
            v-for="point in projectedPublicPoints"
            :key="`ring-${point.id}`"
            :cx="point.x"
            :cy="point.y"
            :r="point.radius * 2.1"
            fill="none"
            :stroke="point.ringColor"
            stroke-width="0.95"
            opacity="0.78"
          />
          <circle
            v-for="point in projectedPublicPoints"
            :key="point.id"
            :cx="point.x"
            :cy="point.y"
            :r="point.radius"
            :fill="point.color"
            stroke="rgba(229, 247, 255, 0.82)"
            stroke-width="0.74"
          />
        </g>

        <g class="map-offmap">
          <line
            v-if="privateBucketCount > 0"
            :x1="originCoord[0]"
            :y1="originCoord[1]"
            :x2="privateCoord[0]"
            :y2="privateCoord[1]"
            stroke="rgba(243, 177, 75, 0.5)"
            stroke-width="1.1"
            stroke-dasharray="5 5"
          />

          <circle
            v-for="node in offMapNodes"
            :key="`halo-${node.id}`"
            :cx="node.x"
            :cy="node.y"
            r="12"
            :fill="node.glow"
            opacity="0.28"
            :filter="`url(#${pointGlowFilterId})`"
          />
          <circle
            v-for="node in offMapNodes"
            :key="node.id"
            :cx="node.x"
            :cy="node.y"
            r="5.5"
            :fill="node.color"
            stroke="rgba(235, 247, 255, 0.78)"
            stroke-width="0.8"
          />

          <text
            v-for="node in offMapNodes"
            :key="`label-${node.id}`"
            :x="node.anchor === 'start' ? node.x + 10 : node.x - 10"
            :y="node.y - 8"
            :text-anchor="node.anchor"
            fill="rgba(225, 238, 255, 0.9)"
            font-size="11px"
            font-weight="600"
          >
            {{ node.label }}
          </text>
        </g>
      </svg>

      <div class="map-legend">
        <span class="legend-item public">Public IP</span>
        <span class="legend-item origin">Scan origin</span>
        <span class="legend-item private">Private bucket</span>
      </div>
    </div>

    <v-row v-if="!mapOnly" class="mt-4" dense>
      <v-col cols="12" md="3">
        <v-card variant="tonal" class="pa-3">
          <div class="text-caption text-medium-emphasis">Total hosts</div>
          <div class="text-h6 font-weight-bold text-primary">{{ summary.total_hosts }}</div>
        </v-card>
      </v-col>
      <v-col cols="12" md="3">
        <v-card variant="tonal" class="pa-3">
          <div class="text-caption text-medium-emphasis">Public hosts</div>
          <div class="text-h6 font-weight-bold text-success">{{ summary.public_hosts }}</div>
        </v-card>
      </v-col>
      <v-col cols="12" md="3">
        <v-card variant="tonal" class="pa-3">
          <div class="text-caption text-medium-emphasis">Private hosts</div>
          <div class="text-h6 font-weight-bold text-warning">{{ summary.private_hosts }}</div>
        </v-card>
      </v-col>
      <v-col cols="12" md="3">
        <v-card variant="tonal" class="pa-3">
          <div class="text-caption text-medium-emphasis">Open ports</div>
          <div class="text-h6 font-weight-bold text-secondary">{{ summary.total_open_ports }}</div>
        </v-card>
      </v-col>
    </v-row>

    <v-table v-if="!mapOnly" density="compact" class="mt-4">
      <thead>
        <tr>
          <th>IP</th>
          <th>Scope</th>
          <th>Region</th>
          <th>Open ports</th>
          <th>Protocols</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="item in latestHosts" :key="item.id">
          <td>{{ item.ip }}</td>
          <td>{{ item.scope }}</td>
          <td>{{ item.region }}</td>
          <td>{{ item.open_port_count }}</td>
          <td>{{ item.protocols }}</td>
        </tr>
        <tr v-if="!latestHosts.length">
          <td colspan="5" class="text-center py-4 text-medium-emphasis">
            No scan hosts yet.
          </td>
        </tr>
      </tbody>
    </v-table>
  </DataPanel>
</template>

<script>
import store from "../state/appStore";
import DataPanel from "./ui/DataPanel.vue";

const GLOBE_SIMPLE_WORLD_STEP = 5;
const GLOBE_ROTATION_SPEED = 4.5;
const GLOBE_FOCUS_OSCILLATION_DEG = 28;
const GLOBE_FOCUS_OSCILLATION_SPEED = 0.6;

export default {
  name: "MapPanel",
  components: {
    DataPanel,
  },
  props: {
    mapOnly: {
      type: Boolean,
      default: false,
    },
    immersive: {
      type: Boolean,
      default: false,
    },
    panelTitle: {
      type: String,
      default: "Scan Geomap",
    },
    panelSubtitle: {
      type: String,
      default: "Public IPs geolocated from real results with WebSocket updates.",
    },
    showRefresh: {
      type: Boolean,
      default: false,
    },
    showPanelHeader: {
      type: Boolean,
      default: true,
    },
    showIntro: {
      type: Boolean,
      default: true,
    },
    showProjectionSwitch: {
      type: Boolean,
      default: false,
    },
    defaultProjection: {
      type: String,
      default: "flat",
    },
  },
  data() {
    return {
      store,
      error: "",
      loading: false,
      lastUpdated: "",
      mapUid: Math.random().toString(36).slice(2, 10),
      mapWidth: 920,
      mapHeight: 470,
      mapPadding: 18,
      wsRefreshTimer: null,
      stopTableRefreshSubscription: null,
      worldGeoJsonDetailed: null,
      worldGeoJsonGlobe: null,
      origin: {
        ip: "127.0.0.1",
        label: "Scan origin",
      },
      publicPoints: [],
      privateHosts: [],
      privateBucketCount: 0,
      geoipStatus: {
        source: "empty",
        rows: 0,
        generated_at: "",
        partial: false,
      },
      summary: {
        total_hosts: 0,
        public_hosts: 0,
        private_hosts: 0,
        unmapped_public_hosts: 0,
        total_ports: 0,
        total_open_ports: 0,
      },
      projectionMode: String(this.defaultProjection || "flat").trim().toLowerCase() === "globe"
        ? "globe"
        : "flat",
      globeRotation: -18,
      globeTilt: 14,
      globeFocusLongitude: -18,
      globeOscillationTime: 0,
      globeFrameId: null,
      globeLastFrameTs: 0,
    };
  },
  computed: {
    apiBase() {
      return this.store.state.apiBase;
    },
    isGlobeMode() {
      return this.projectionMode === "globe";
    },
    projectionLabel() {
      return this.isGlobeMode ? "Projection: Globe" : "Projection: Flat";
    },
    oceanGradientId() {
      return `map-ocean-${this.mapUid}`;
    },
    globeOceanGradientId() {
      return `map-globe-ocean-${this.mapUid}`;
    },
    globeAtmosphereGradientId() {
      return `map-globe-atmosphere-${this.mapUid}`;
    },
    globeClipId() {
      return `map-globe-clip-${this.mapUid}`;
    },
    landGradientId() {
      return `map-land-${this.mapUid}`;
    },
    frameGradientId() {
      return `map-frame-${this.mapUid}`;
    },
    arcGlowFilterId() {
      return `map-arc-glow-${this.mapUid}`;
    },
    pointGlowFilterId() {
      return `map-point-glow-${this.mapUid}`;
    },
    wsLabel() {
      const wsState = String(this.store.state.wsStatus || "").trim().toLowerCase();
      if (wsState === "online") return "WS online";
      if (wsState === "error") return "WS error";
      if (wsState === "offline") return "WS reconnecting";
      return "WS connecting";
    },
    geoipSourceLabel() {
      const source = String(this.geoipStatus.source || "").trim().toLowerCase();
      if (source === "repo-seed-file") return "GeoIP repo seed";
      if (source === "fallback-rir-seed") return "GeoIP fallback";
      if (source === "external-db") return "GeoIP local DB";
      return "GeoIP pending";
    },
    statusInfoText() {
      const parts = [];
      if (this.wsLabel) parts.push(this.wsLabel);
      if (this.geoipSourceLabel) parts.push(this.geoipSourceLabel);
      return parts.join(" · ");
    },
    geoipInfoText() {
      const parts = [];
      const rows = Number(this.geoipStatus.rows) || 0;
      if (rows > 0) parts.push(`${rows.toLocaleString()} blocks`);
      if (this.geoipStatus.generated_at) parts.push(`seed ${this.geoipStatus.generated_at}`);
      if (this.geoipStatus.partial) parts.push("partial catalog");
      return parts.join(" · ");
    },
    graticuleLatitudes() {
      return [-60, -30, 0, 30, 60];
    },
    graticuleLongitudes() {
      return [-120, -60, 0, 60, 120];
    },
    globeCenterX() {
      return this.mapWidth / 2;
    },
    globeCenterY() {
      return this.mapHeight / 2 + 10;
    },
    globeRadius() {
      return Math.min(this.mapWidth, this.mapHeight) * 0.34;
    },
    originCoord() {
      if (this.isGlobeMode) {
        return [Math.round(this.mapWidth * 0.11), Math.round(this.mapHeight * 0.2)];
      }
      return [10, Math.round(this.mapHeight * 0.5)];
    },
    privateCoord() {
      if (this.isGlobeMode) {
        return [Math.round(this.mapWidth * 0.89), Math.round(this.mapHeight * 0.82)];
      }
      return [this.mapWidth - 10, Math.round(this.mapHeight * 0.78)];
    },
    projectedPublicPoints() {
      const points = this.publicPoints
        .map((item) => {
          const lon = Number(item.lon);
          const lat = Number(item.lat);
          if (!Number.isFinite(lon) || !Number.isFinite(lat)) return null;
          const projected = this.projectPoint(lon, lat);
          if (!projected) return null;
          const depth = Number.isFinite(projected.depth) ? projected.depth : 1;
          return {
            ...item,
            id: `public-${item.ip}`,
            x: projected.x,
            y: projected.y,
            depth,
            color: this.pointColor(item, depth),
            glowColor: this.pointGlowColor(item, depth),
            ringColor: this.pointRingColor(item, depth),
            radius: this.pointRadius(item, depth),
          };
        })
        .filter(Boolean)
        .slice(0, 400);
      if (this.isGlobeMode) {
        points.sort((a, b) => a.depth - b.depth);
      }
      return points;
    },
    globeLatitudePaths() {
      if (!this.isGlobeMode) return [];
      return this.graticuleLatitudes
        .map((lat) => ({
          id: `globe-lat-${lat}`,
          d: this.buildGlobeLatitudePath(lat),
        }))
        .filter((item) => item.d);
    },
    globeLongitudePaths() {
      if (!this.isGlobeMode) return [];
      return this.graticuleLongitudes
        .map((lon) => ({
          id: `globe-lon-${lon}`,
          d: this.buildGlobeLongitudePath(lon),
        }))
        .filter((item) => item.d);
    },
    worldPaths() {
      const collection = this.isGlobeMode ? this.worldGeoJsonGlobe : this.worldGeoJsonDetailed;
      const features = Array.isArray(collection && collection.features) ? collection.features : [];
      const paths = [];
      features.forEach((feature, featureIndex) => {
        const geometry = feature && feature.geometry ? feature.geometry : null;
        const featurePaths = this.isGlobeMode
          ? this.geometryToPathsGlobe(geometry)
          : this.geometryToPathsFlat(geometry);
        featurePaths.forEach((d, pathIndex) => {
          if (!d) return;
          paths.push({
            id: `land-${featureIndex}-${pathIndex}`,
            d,
          });
        });
      });
      return paths;
    },
    arcPaths() {
      return this.projectedPublicPoints.map((item, index) => {
        const openPorts = Number(item.open_port_count) || 0;
        return {
          id: `arc-${item.ip}`,
          d: this.buildArcPath(this.originCoord[0], this.originCoord[1], item.x, item.y),
          stroke: openPorts >= 20 ? "rgba(255,84,104,0.9)" : "rgba(74,136,255,0.76)",
          glow: openPorts >= 20 ? "rgba(255,84,104,0.44)" : "rgba(74,136,255,0.32)",
          strokeWidth: openPorts >= 20 ? 1.9 : 1.2,
          traceColor: openPorts >= 20 ? "rgba(255,153,167,0.96)" : "rgba(122,210,255,0.96)",
          traceRadius: openPorts >= 20 ? 3.2 : 2.8,
          duration: `${(3.2 + ((index % 7) * 0.34)).toFixed(2)}s`,
          begin: `${(index % 9) * 0.18}s`,
          style: {
            animationDuration: `${(2.8 + ((index % 6) * 0.28)).toFixed(2)}s`,
            animationDelay: `${(index % 5) * 0.14}s`,
          },
        };
      });
    },
    offMapNodes() {
      return [
        {
          id: "origin",
          x: this.originCoord[0],
          y: this.originCoord[1],
          label: `${this.origin.label || "Scan origin"} (${this.origin.ip || "n/a"})`,
          color: "rgba(52, 230, 255, 0.95)",
          glow: "rgba(52, 230, 255, 0.54)",
          anchor: "start",
        },
        {
          id: "private-bucket",
          x: this.privateCoord[0],
          y: this.privateCoord[1],
          label: `Private IP bucket (${this.privateBucketCount})`,
          color: "rgba(243, 177, 75, 0.95)",
          glow: "rgba(243, 177, 75, 0.48)",
          anchor: "end",
        },
      ];
    },
    latestHosts() {
      const publicRows = this.publicPoints.map((item) => ({
        id: `pub-${item.ip}`,
        ip: item.ip,
        scope: "public",
        region: `${item.rir || "RIR"} ${item.country || ""}`.trim(),
        open_port_count: Number(item.open_port_count) || 0,
        protocols: Array.isArray(item.protocols) ? item.protocols.join(", ") : "",
      }));
      const privateRows = this.privateHosts.map((item) => ({
        id: `priv-${item.ip}`,
        ip: item.ip,
        scope: "private",
        region: "private/reserved",
        open_port_count: Number(item.open_port_count) || 0,
        protocols: Array.isArray(item.protocols) ? item.protocols.join(", ") : "",
      }));
      return [...publicRows, ...privateRows]
        .sort((a, b) => b.open_port_count - a.open_port_count || a.ip.localeCompare(b.ip))
        .slice(0, 10);
    },
  },
  watch: {
    apiBase() {
      this.reloadData();
    },
    defaultProjection(value) {
      this.setProjection(value);
    },
    projectionMode() {
      this.syncProjectionAnimation();
    },
  },
  mounted() {
    this.loadWorldGeometry();
    this.reloadData();
    this.syncProjectionAnimation();
    this.stopTableRefreshSubscription = this.store.subscribeTableRefresh(
      this.handleWsRefresh
    );
  },
  beforeUnmount() {
    if (this.wsRefreshTimer) {
      clearTimeout(this.wsRefreshTimer);
      this.wsRefreshTimer = null;
    }
    this.stopGlobeRotation();
    if (typeof this.stopTableRefreshSubscription === "function") {
      this.stopTableRefreshSubscription();
      this.stopTableRefreshSubscription = null;
    }
  },
  methods: {
    assetBaseUrl() {
      const base =
        typeof process !== "undefined" && process.env && process.env.BASE_URL
          ? process.env.BASE_URL
          : "/";
      return String(base).replace(/\/?$/, "/");
    },
    worldGeoJsonUrlCandidates(kind) {
      const base = this.assetBaseUrl();
      if (kind === "globe") {
        return [`${base}geo/world-detailed.geojson`, `${base}geo/world.geojson`];
      }
      return [`${base}geo/world-detailed.geojson`, `${base}geo/world.geojson`];
    },
    loadGeoJson(candidates, assign) {
      const tryNext = (index = 0) => {
        if (index >= candidates.length) {
          return Promise.resolve(null);
        }
        return fetch(candidates[index])
          .then((res) => {
            if (!res.ok) {
              throw new Error(`HTTP ${res.status}`);
            }
            return res.json();
          })
          .then((payload) => {
            if (!payload || payload.type !== "FeatureCollection") {
              throw new Error("Invalid GeoJSON payload");
            }
            assign(payload);
            return payload;
          })
          .catch(() => tryNext(index + 1));
      };
      return tryNext();
    },
    loadWorldGeometry() {
      return Promise.all([
        this.loadGeoJson(this.worldGeoJsonUrlCandidates("detailed"), (payload) => {
          this.worldGeoJsonDetailed = payload;
        }),
        this.loadGeoJson(this.worldGeoJsonUrlCandidates("globe"), (payload) => {
          this.worldGeoJsonGlobe = payload;
        }),
      ]);
    },
    setProjection(mode) {
      this.projectionMode = String(mode || "flat").trim().toLowerCase() === "globe" ? "globe" : "flat";
    },
    syncProjectionAnimation() {
      if (this.isGlobeMode) {
        this.startGlobeRotation();
        return;
      }
      this.stopGlobeRotation();
    },
    startGlobeRotation() {
      this.stopGlobeRotation();
      this.globeLastFrameTs = 0;
      const tick = (timestamp) => {
        if (!this.isGlobeMode) {
          this.globeFrameId = null;
          return;
        }
        if (!this.globeLastFrameTs) {
          this.globeLastFrameTs = timestamp;
        }
        const delta = Math.min(64, timestamp - this.globeLastFrameTs);
        this.globeLastFrameTs = timestamp;
        const hasPublicFocus = Array.isArray(this.publicPoints) && this.publicPoints.length > 0;
        if (hasPublicFocus) {
          this.globeOscillationTime += (delta / 1000) * GLOBE_FOCUS_OSCILLATION_SPEED;
          this.globeRotation = this.normalizeLongitude(
            this.globeFocusLongitude + (Math.sin(this.globeOscillationTime) * GLOBE_FOCUS_OSCILLATION_DEG)
          );
        } else {
          this.globeRotation = this.normalizeLongitude(
            this.globeRotation + ((delta / 1000) * GLOBE_ROTATION_SPEED)
          );
        }
        this.globeFrameId = window.requestAnimationFrame(tick);
      };
      this.globeFrameId = window.requestAnimationFrame(tick);
    },
    stopGlobeRotation() {
      if (this.globeFrameId !== null) {
        window.cancelAnimationFrame(this.globeFrameId);
        this.globeFrameId = null;
      }
      this.globeLastFrameTs = 0;
      this.globeOscillationTime = 0;
    },
    latitudeToY(lat) {
      const clipped = Math.max(-85, Math.min(85, Number(lat) || 0));
      const usableHeight = this.mapHeight - (this.mapPadding * 2);
      return this.mapPadding + ((90 - clipped) / 180) * usableHeight;
    },
    longitudeToX(lon) {
      const clipped = Math.max(-180, Math.min(180, Number(lon) || 0));
      const usableWidth = this.mapWidth - (this.mapPadding * 2);
      return this.mapPadding + ((clipped + 180) / 360) * usableWidth;
    },
    normalizeLongitude(lon) {
      let value = Number(lon) || 0;
      while (value > 180) value -= 360;
      while (value < -180) value += 360;
      return value;
    },
    degToRad(value) {
      return (Number(value) || 0) * (Math.PI / 180);
    },
    projectPointFlat(lon, lat) {
      const x = this.longitudeToX(lon);
      const y = this.latitudeToY(lat);
      if (!Number.isFinite(x) || !Number.isFinite(y)) return null;
      return { x, y, depth: 1 };
    },
    projectPointGlobe(lon, lat, allowBackface = false) {
      const lambda = this.degToRad(this.normalizeLongitude((Number(lon) || 0) - this.globeRotation));
      const phi = this.degToRad(Math.max(-89.5, Math.min(89.5, Number(lat) || 0)));
      const phi0 = this.degToRad(this.globeTilt);
      const cosPhi = Math.cos(phi);
      const sinPhi = Math.sin(phi);
      const cosPhi0 = Math.cos(phi0);
      const sinPhi0 = Math.sin(phi0);
      const cosLambda = Math.cos(lambda);
      const sinLambda = Math.sin(lambda);
      const visibility = (sinPhi0 * sinPhi) + (cosPhi0 * cosPhi * cosLambda);
      if (!allowBackface && visibility <= 0) return null;
      const x = this.globeCenterX + (this.globeRadius * cosPhi * sinLambda);
      const y = this.globeCenterY - (this.globeRadius * ((cosPhi0 * sinPhi) - (sinPhi0 * cosPhi * cosLambda)));
      if (!Number.isFinite(x) || !Number.isFinite(y)) return null;
      return { x, y, depth: Math.max(0.08, visibility) };
    },
    projectPoint(lon, lat) {
      return this.isGlobeMode ? this.projectPointGlobe(lon, lat) : this.projectPointFlat(lon, lat);
    },
    geometryToPathsFlat(geometry) {
      const geom = geometry && typeof geometry === "object" ? geometry : null;
      if (!geom || !Array.isArray(geom.coordinates)) return [];
      if (geom.type === "Polygon") {
        const path = this.polygonToPathFlat(geom.coordinates);
        return path ? [path] : [];
      }
      if (geom.type === "MultiPolygon") {
        return geom.coordinates.map((polygon) => this.polygonToPathFlat(polygon)).filter(Boolean);
      }
      return [];
    },
    polygonToPathFlat(polygon) {
      if (!Array.isArray(polygon)) return "";
      return polygon.map((ring) => this.ringToPathFlat(ring)).filter(Boolean).join(" ");
    },
    ringToPathFlat(ring) {
      if (!Array.isArray(ring) || ring.length < 2) return "";
      let path = "";
      let prevLon = null;
      let started = false;
      ring.forEach((pair, index) => {
        if (!Array.isArray(pair) || pair.length < 2) return;
        const lon = Number(pair[0]);
        const lat = Number(pair[1]);
        if (!Number.isFinite(lon) || !Number.isFinite(lat)) return;
        const projected = this.projectPointFlat(lon, lat);
        if (!projected) return;
        const command =
          !started || index === 0 || (prevLon !== null && Math.abs(lon - prevLon) > 180)
            ? "M"
            : "L";
        path += `${command}${projected.x.toFixed(2)},${projected.y.toFixed(2)} `;
        prevLon = lon;
        started = true;
      });
      return path ? `${path.trim()} Z` : "";
    },
    geometryToPathsGlobe(geometry) {
      const geom = geometry && typeof geometry === "object" ? geometry : null;
      if (!geom || !Array.isArray(geom.coordinates)) return [];
      if (geom.type === "Polygon") {
        return this.polygonToPathGlobe(geom.coordinates);
      }
      if (geom.type === "MultiPolygon") {
        return geom.coordinates.flatMap((polygon) => this.polygonToPathGlobe(polygon));
      }
      return [];
    },
    polygonToPathGlobe(polygon) {
      if (!Array.isArray(polygon)) return [];
      return polygon.flatMap((ring) => this.ringToPathsGlobe(ring));
    },
    ringToPathsGlobe(ring) {
      if (!Array.isArray(ring) || ring.length < 2) return [];
      const segments = [];
      let current = [];
      ring.forEach((pair) => {
        if (!Array.isArray(pair) || pair.length < 2) return;
        const projected = this.projectPointGlobe(Number(pair[0]), Number(pair[1]));
        if (projected) {
          current.push(projected);
          return;
        }
        if (current.length >= 2) {
          segments.push(current.slice());
        }
        current = [];
      });
      if (current.length >= 2) {
        segments.push(current.slice());
      }
      return segments
        .map((segment) => {
          if (segment.length < 2) return "";
          const commands = segment
            .map((point, index) => `${index === 0 ? "M" : "L"}${point.x.toFixed(2)},${point.y.toFixed(2)}`)
            .join(" ");
          return `${commands} Z`;
        })
        .filter(Boolean);
    },
    buildGlobeLatitudePath(lat) {
      const points = [];
      for (let lon = -180; lon <= 180; lon += GLOBE_SIMPLE_WORLD_STEP) {
        const projected = this.projectPointGlobe(lon, lat);
        points.push(projected);
      }
      return this.sampleProjectedLine(points);
    },
    buildGlobeLongitudePath(lon) {
      const points = [];
      for (let lat = -85; lat <= 85; lat += GLOBE_SIMPLE_WORLD_STEP) {
        const projected = this.projectPointGlobe(lon, lat);
        points.push(projected);
      }
      return this.sampleProjectedLine(points);
    },
    sampleProjectedLine(points) {
      let path = "";
      let drawing = false;
      points.forEach((point) => {
        if (!point) {
          drawing = false;
          return;
        }
        path += `${drawing ? "L" : "M"}${point.x.toFixed(2)},${point.y.toFixed(2)} `;
        drawing = true;
      });
      return path.trim();
    },
    buildArcPath(sx, sy, tx, ty) {
      if (!this.isGlobeMode) {
        const cx = (sx + tx) / 2;
        const cy = (sy + ty) / 2 - Math.min(90, Math.abs(tx - sx) * 0.18 + 16);
        return `M${sx},${sy} Q${cx},${cy} ${tx},${ty}`;
      }
      const mx = (sx + tx) / 2;
      const my = (sy + ty) / 2;
      const vx = mx - this.globeCenterX;
      const vy = my - this.globeCenterY;
      const length = Math.hypot(vx, vy) || 1;
      const lift = Math.min(130, 42 + (Math.hypot(tx - sx, ty - sy) * 0.18));
      const cx = mx + ((vx / length) * lift);
      const cy = my + ((vy / length) * lift) - 10;
      return `M${sx},${sy} Q${cx},${cy} ${tx},${ty}`;
    },
    pointColor(item, depth = 1) {
      const weight = Number(item.open_port_count) || 0;
      const alphaBoost = this.isGlobeMode ? Math.min(1, 0.56 + (depth * 0.5)) : 0.95;
      if (weight >= 20) return `rgba(255, 84, 104, ${alphaBoost})`;
      if (weight >= 10) return `rgba(243, 177, 75, ${alphaBoost})`;
      return `rgba(53, 230, 177, ${Math.min(1, alphaBoost)})`;
    },
    pointGlowColor(item, depth = 1) {
      const weight = Number(item.open_port_count) || 0;
      const alpha = this.isGlobeMode ? (0.22 + (depth * 0.34)) : 0.52;
      if (weight >= 20) return `rgba(255, 84, 104, ${alpha.toFixed(3)})`;
      if (weight >= 10) return `rgba(243, 177, 75, ${Math.min(0.72, alpha + 0.08).toFixed(3)})`;
      return `rgba(53, 230, 177, ${Math.min(0.62, alpha).toFixed(3)})`;
    },
    pointRingColor(item, depth = 1) {
      const weight = Number(item.open_port_count) || 0;
      const alpha = this.isGlobeMode ? Math.min(0.94, 0.36 + (depth * 0.46)) : 0.84;
      if (weight >= 20) return `rgba(255, 155, 168, ${alpha.toFixed(3)})`;
      if (weight >= 10) return `rgba(255, 214, 145, ${Math.min(0.9, alpha).toFixed(3)})`;
      return `rgba(147, 255, 224, ${Math.min(0.88, alpha).toFixed(3)})`;
    },
    pointRadius(item, depth = 1) {
      const weight = Number(item.open_port_count) || 0;
      const base = weight >= 20 ? 4.2 : weight >= 10 ? 3.4 : 2.8;
      if (!this.isGlobeMode) return base;
      return base * (0.78 + (depth * 0.48));
    },
    deriveGlobeFocus(points) {
      const rows = Array.isArray(points) ? points : [];
      if (!rows.length) {
        return {
          longitude: this.globeFocusLongitude,
          tilt: 14,
        };
      }
      let sinSum = 0;
      let cosSum = 0;
      let latSum = 0;
      let totalWeight = 0;
      rows.forEach((item) => {
        const lon = Number(item && item.lon);
        const lat = Number(item && item.lat);
        if (!Number.isFinite(lon) || !Number.isFinite(lat)) return;
        const weight = Math.max(1, Number(item && item.open_port_count) || 0);
        const radians = this.degToRad(lon);
        sinSum += Math.sin(radians) * weight;
        cosSum += Math.cos(radians) * weight;
        latSum += lat * weight;
        totalWeight += weight;
      });
      if (!totalWeight || (!sinSum && !cosSum)) {
        return {
          longitude: this.globeFocusLongitude,
          tilt: 14,
        };
      }
      const longitude = this.normalizeLongitude(Math.atan2(sinSum, cosSum) * (180 / Math.PI));
      const avgLat = latSum / totalWeight;
      return {
        longitude,
        tilt: Math.max(-28, Math.min(32, avgLat * 0.58)),
      };
    },
    applySnapshot(snapshot) {
      const data = snapshot && snapshot.data ? snapshot.data : snapshot;
      const summary = (data && data.summary) || {};
      this.origin = (data && data.origin) || { ip: "127.0.0.1", label: "Scan origin" };
      this.publicPoints = Array.isArray(data && data.public_points) ? data.public_points : [];
      this.privateHosts = Array.isArray(data && data.private_hosts) ? data.private_hosts : [];
      this.geoipStatus = (data && data.geoip) || {
        source: "empty",
        rows: 0,
        generated_at: "",
        partial: false,
      };
      const privateBucket = (data && data.private_bucket) || {};
      this.privateBucketCount = Number(privateBucket.count) || this.privateHosts.length;
      const focus = this.deriveGlobeFocus(this.publicPoints);
      this.globeFocusLongitude = focus.longitude;
      this.globeTilt = focus.tilt;
      if (this.isGlobeMode && this.publicPoints.length) {
        this.globeRotation = focus.longitude;
        this.globeOscillationTime = 0;
      }
      this.summary = {
        total_hosts: Number(summary.total_hosts) || 0,
        public_hosts: Number(summary.public_hosts) || 0,
        private_hosts: Number(summary.private_hosts) || 0,
        unmapped_public_hosts: Number(summary.unmapped_public_hosts) || 0,
        total_ports: Number(summary.total_ports) || 0,
        total_open_ports: Number(summary.total_open_ports) || 0,
      };
      this.lastUpdated = new Date().toLocaleTimeString();
    },
    reloadData() {
      this.loading = true;
      this.error = "";
      return this.store
        .fetchJsonPromise("/api/map/scan?limit=500")
        .then((payload) => {
          this.applySnapshot(payload && payload.data ? payload.data : payload);
        })
        .catch((err) => {
          this.error = err.message || "Failed to load scan map data.";
          this.lastUpdated = "";
        })
        .finally(() => {
          this.loading = false;
        });
    },
    manualRefresh() {
      return this.reloadData();
    },
    handleWsRefresh() {
      if (this.loading) return;
      if (this.wsRefreshTimer) return;
      this.wsRefreshTimer = setTimeout(() => {
        this.wsRefreshTimer = null;
        this.reloadData();
      }, 450);
    },
  },
};
</script>

<style scoped>
.map-intro {
  position: relative;
  display: grid;
  gap: 8px;
}

.map-intro__eyebrow {
  color: rgba(108, 229, 255, 0.88);
  font-size: 0.72rem;
  font-weight: 700;
  letter-spacing: 0.18em;
  text-transform: uppercase;
}

.map-intro__title {
  color: rgba(240, 247, 255, 0.98);
  font-size: clamp(1.2rem, 2vw, 1.55rem);
  font-weight: 600;
  letter-spacing: 0.01em;
}

.map-intro__description {
  color: rgba(188, 208, 227, 0.82);
  font-size: 0.98rem;
  line-height: 1.6;
}

.map-intro__meta {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
  color: rgba(132, 173, 205, 0.86);
  font-size: 0.78rem;
  letter-spacing: 0.05em;
  text-transform: uppercase;
}

.map-intro__meta-divider {
  width: 4px;
  height: 4px;
  border-radius: 999px;
  background: rgba(91, 217, 255, 0.58);
  box-shadow: 0 0 14px rgba(91, 217, 255, 0.42);
}

.map-wrapper {
  position: relative;
  border-radius: 24px;
  overflow: hidden;
  border: 1px solid rgba(94, 176, 226, 0.24);
  background: radial-gradient(
      125% 140% at 0% 0%,
      rgba(69, 173, 255, 0.28),
      rgba(8, 16, 28, 0.16) 46%,
      rgba(4, 10, 18, 0.95) 100%
    ),
    radial-gradient(
      120% 120% at 100% 0%,
      rgba(255, 173, 82, 0.12),
      rgba(255, 173, 82, 0) 42%
    ),
    linear-gradient(175deg, rgba(4, 14, 28, 0.99), rgba(3, 9, 17, 0.98));
  box-shadow:
    inset 0 0 0 1px rgba(255, 255, 255, 0.03),
    inset 0 30px 80px rgba(47, 124, 196, 0.06),
    0 24px 60px rgba(4, 8, 15, 0.5);
}

.map-wrapper::before {
  content: "";
  position: absolute;
  inset: 0;
  pointer-events: none;
  background: linear-gradient(
    180deg,
    rgba(140, 218, 255, 0.06) 0%,
    rgba(140, 218, 255, 0) 26%,
    rgba(140, 218, 255, 0.08) 100%
  );
  z-index: 1;
}

.map-wrapper::after {
  content: "";
  position: absolute;
  inset: -20% 0 auto;
  height: 42%;
  pointer-events: none;
  background: linear-gradient(
    180deg,
    rgba(102, 222, 255, 0),
    rgba(102, 222, 255, 0.1),
    rgba(102, 222, 255, 0)
  );
  mix-blend-mode: screen;
  opacity: 0.55;
  transform: translateY(-100%);
  animation: map-scan 9s linear infinite;
  z-index: 1;
}

.map-wrapper--globe {
  background: radial-gradient(
      120% 120% at 50% 0%,
      rgba(69, 173, 255, 0.18),
      rgba(8, 16, 28, 0.1) 46%,
      rgba(4, 10, 18, 0.98) 100%
    ),
    radial-gradient(
      80% 80% at 50% 50%,
      rgba(36, 112, 194, 0.16),
      rgba(4, 10, 18, 0) 58%
    ),
    linear-gradient(180deg, rgba(4, 14, 28, 0.99), rgba(3, 9, 17, 0.98));
}

.map-overlay {
  position: absolute;
  top: 16px;
  left: 16px;
  right: 16px;
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 12px;
  flex-wrap: wrap;
  z-index: 3;
}

.map-overlay__group {
  display: grid;
  gap: 8px;
}

.map-overlay__label {
  color: rgba(162, 206, 229, 0.86);
  font-size: 0.7rem;
  font-weight: 700;
  letter-spacing: 0.14em;
  text-transform: uppercase;
}

.map-projection-toggle {
  padding: 4px;
  border-radius: 999px;
  background: rgba(6, 14, 28, 0.72);
  border: 1px solid rgba(102, 188, 229, 0.16);
  backdrop-filter: blur(10px);
}

.map-overlay__meta {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  justify-content: flex-end;
}

.map-status-pill {
  padding: 6px 12px;
  border-radius: 999px;
  border: 1px solid rgba(98, 185, 230, 0.18);
  background: linear-gradient(180deg, rgba(6, 15, 31, 0.84), rgba(5, 10, 18, 0.76));
  color: rgba(220, 239, 255, 0.94);
  font-size: 0.72rem;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  backdrop-filter: blur(10px);
  box-shadow: 0 14px 30px rgba(2, 8, 14, 0.26);
}

.map-refresh-btn {
  min-height: 34px;
}

.map-status-pill--accent {
  color: rgba(144, 244, 208, 0.96);
}

.map-wrapper svg {
  display: block;
  width: 100%;
  height: clamp(300px, 42vw, 520px);
  aspect-ratio: 2 / 1;
  position: relative;
  z-index: 0;
}

.map-wrapper--immersive svg {
  height: clamp(460px, 78vh, 920px);
}

.map-wrapper--globe svg {
  height: clamp(360px, 54vw, 720px);
}

.map-wrapper--immersive.map-wrapper--globe svg {
  height: clamp(540px, 82vh, 980px);
}

.map-wrapper--immersive {
  border-radius: 28px;
  box-shadow:
    inset 0 0 0 1px rgba(255, 255, 255, 0.03),
    inset 0 40px 120px rgba(47, 124, 196, 0.08),
    0 30px 80px rgba(4, 8, 15, 0.58);
}

.map-land {
  opacity: 0.94;
}

.map-land--globe {
  opacity: 0.96;
}

.map-arc-flow {
  stroke-dasharray: 10 12;
  animation: arc-flow 3.2s linear infinite;
}

.map-arc-trace {
  opacity: 0.96;
}

.map-legend {
  position: absolute;
  right: 18px;
  bottom: 18px;
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  max-width: 320px;
  padding: 10px 12px;
  border: 1px solid rgba(106, 192, 231, 0.16);
  border-radius: 18px;
  background: linear-gradient(180deg, rgba(6, 14, 28, 0.82), rgba(5, 10, 20, 0.7));
  backdrop-filter: blur(10px);
  box-shadow:
    inset 0 0 0 1px rgba(255, 255, 255, 0.02),
    0 14px 30px rgba(4, 9, 18, 0.38);
  z-index: 2;
}

.legend-item {
  border-radius: 999px;
  border: 1px solid transparent;
  padding: 4px 10px;
  font-size: 0.7rem;
  font-weight: 600;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  background: rgba(5, 12, 24, 0.82);
  backdrop-filter: blur(6px);
  box-shadow: 0 0 0 1px rgba(255, 255, 255, 0.02);
}

.legend-item.public {
  border-color: rgba(53, 230, 177, 0.82);
  color: rgba(132, 248, 213, 0.95);
}

.legend-item.origin {
  border-color: rgba(52, 230, 255, 0.9);
  color: rgba(154, 241, 255, 0.95);
}

.legend-item.private {
  border-color: rgba(243, 177, 75, 0.9);
  color: rgba(255, 211, 140, 0.95);
}

@keyframes map-scan {
  from {
    transform: translateY(-110%);
  }
  to {
    transform: translateY(240%);
  }
}

@keyframes arc-flow {
  from {
    stroke-dashoffset: 48;
  }
  to {
    stroke-dashoffset: 0;
  }
}

@media (max-width: 960px) {
  .map-overlay {
    top: 12px;
    left: 12px;
    right: 12px;
  }

  .map-wrapper--immersive svg,
  .map-wrapper--immersive.map-wrapper--globe svg {
    height: clamp(460px, 74vh, 820px);
  }
}

@media (max-width: 780px) {
  .map-intro__description {
    font-size: 0.92rem;
  }

  .map-overlay {
    gap: 10px;
  }

  .map-overlay__meta {
    justify-content: flex-start;
  }

  .map-legend {
    right: 12px;
    bottom: 12px;
    max-width: calc(100% - 24px);
  }

  .legend-item,
  .map-status-pill {
    font-size: 0.65rem;
  }
}
</style>
