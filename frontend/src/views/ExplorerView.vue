<template>
  <div>
    <ViewHeader
      overline="Explorer"
      title="Shodan-Style Search"
      description="Search targets, services, banners, tags and favicons from one place."
      :refresh-loading="loading"
      @refresh="load"
    />

    <DataPanel
      title="Global Explorer"
      subtitle="Unified search over all collected artifacts."
      :loading="loading"
      :error="error"
      :last-updated="lastUpdated"
      @refresh="load"
    >
      <template #skeleton>
        <v-skeleton-loader type="heading, table-thead, table-row@8" class="skeleton-block" />
      </template>

      <v-row dense>
        <v-col cols="12" md="6">
          <v-text-field
            v-model.trim="filters.query"
            label="Global query"
            placeholder="IP, port, banner, tag, network..."
            prepend-inner-icon="mdi-magnify"
            :loading="loading"
            clearable
            variant="outlined"
            density="comfortable"
          />
        </v-col>
        <v-col cols="12" md="2">
          <v-select
            v-model="filters.proto"
            :items="protoOptions"
            label="Proto"
            item-title="label"
            item-value="value"
            :loading="loading"
            clearable
            variant="outlined"
            density="comfortable"
          />
        </v-col>
        <v-col cols="12" md="2">
          <v-select
            v-model="filters.state"
            :items="stateOptions"
            label="State"
            item-title="label"
            item-value="value"
            :loading="loading"
            clearable
            variant="outlined"
            density="comfortable"
          />
        </v-col>
        <v-col cols="12" md="2" class="explorer-filter-action">
          <v-btn
            class="explorer-clear-btn"
            variant="outlined"
            block
            prepend-icon="mdi-filter-remove"
            :disabled="loading"
            @click="clearFilters"
          >
            Clear
          </v-btn>
        </v-col>
      </v-row>

      <v-row dense class="mt-1 mb-2">
        <v-col cols="12" md="3">
          <v-switch
            v-model="filters.onlyWithBanner"
            hide-details
            density="compact"
            color="info"
            label="Only with banner"
            :disabled="loading"
          />
        </v-col>
        <v-col cols="12" md="3">
          <v-switch
            v-model="filters.onlyWithFavicon"
            hide-details
            density="compact"
            color="success"
            label="Only with favicon"
            :disabled="loading"
          />
        </v-col>
        <v-col cols="12" md="6" class="d-flex flex-wrap ga-2 align-center">
          <v-chip size="small" variant="tonal">Hosts: {{ summary.hosts }}</v-chip>
          <v-chip size="small" variant="tonal">Services: {{ summary.services }}</v-chip>
          <v-chip size="small" variant="tonal">Targets: {{ summary.targets }}</v-chip>
          <v-chip size="small" variant="tonal">Banners: {{ summary.banners }}</v-chip>
          <v-chip size="small" variant="tonal">Tags: {{ summary.tags }}</v-chip>
          <v-chip size="small" variant="tonal">Favicons: {{ summary.favicons }}</v-chip>
        </v-col>
      </v-row>

      <v-tabs v-model="tab" color="primary" class="mt-2">
        <v-tab value="services" :disabled="loading">Services</v-tab>
        <v-tab value="targets" :disabled="loading">Targets</v-tab>
        <v-tab value="banners" :disabled="loading">Banners</v-tab>
        <v-tab value="tags" :disabled="loading">Tags</v-tab>
        <v-tab value="favicons" :disabled="loading">Favicons</v-tab>
      </v-tabs>

      <v-window v-model="tab" class="mt-4">
        <v-window-item value="services">
          <v-table density="compact" class="explorer-table">
            <thead>
              <tr>
                <th>IP</th>
                <th>Port</th>
                <th>Proto</th>
                <th>State</th>
                <th>Banner</th>
                <th>Tags</th>
                <th>Favicon</th>
                <th>Progress</th>
                <th>Intel</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="row in pagedFilteredServices" :key="row.id">
                <td>{{ row.ip }}</td>
                <td>{{ row.port }}</td>
                <td>{{ row.proto }}</td>
                <td>{{ row.state }}</td>
                <td>
                  <span class="ellipsis-cell">{{ row.banner || "-" }}</span>
                </td>
                <td>
                  <span class="ellipsis-cell">{{ row.tags_text || "-" }}</span>
                </td>
                <td>
                  <button
                    v-if="row.favicon_id"
                    type="button"
                    class="favicon-button"
                    title="Open favicon"
                    :aria-label="`Open favicon ${row.favicon_id}`"
                    @click="openFaviconById(row.favicon_id)"
                  >
                    <img :src="faviconSrcById(row.favicon_id)" alt="favicon" class="favicon-thumb" />
                  </button>
                  <span v-else>-</span>
                </td>
                <td>{{ formatProgress(row.progress) }}</td>
                <td>
                  <v-btn
                    size="x-small"
                    variant="tonal"
                    color="primary"
                    prepend-icon="mdi-crosshairs-gps"
                    :loading="isIntelLoadingForIp(row.ip)"
                    @click="openIpIntel(row.ip)"
                  >
                    Intel
                  </v-btn>
                </td>
              </tr>
              <tr v-if="!filteredServices.length">
                <td colspan="9" class="text-medium-emphasis py-4 text-center">
                  No services match current filters
                </td>
              </tr>
            </tbody>
          </v-table>
          <div class="d-flex justify-center mt-3" v-if="servicesPageCount > 1">
            <v-pagination
              v-model="pagination.services"
              :length="servicesPageCount"
              density="comfortable"
              total-visible="7"
            />
          </div>
        </v-window-item>

        <v-window-item value="targets">
          <v-table density="compact" class="explorer-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Network</th>
                <th>Type</th>
                <th>Proto</th>
                <th>Port scope</th>
                <th>Status</th>
                <th>Progress</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="row in pagedFilteredTargets" :key="row.id">
                <td>{{ row.id }}</td>
                <td>{{ row.network }}</td>
                <td>{{ row.type }}</td>
                <td>{{ row.proto }}</td>
                <td>{{ formatTargetPortScope(row) }}</td>
                <td>{{ row.status }}</td>
                <td>{{ formatProgress(row.progress) }}</td>
                <td>
                  <div class="target-inline-actions">
                    <v-btn
                      size="x-small"
                      color="success"
                      variant="tonal"
                      :loading="isTargetActionLoading(row.id, 'start')"
                      :disabled="loading || normalizeTargetStatus(row.status) === 'active'"
                      @click="runTargetAction(row, 'start')"
                    >
                      Start
                    </v-btn>
                    <v-btn
                      size="x-small"
                      color="warning"
                      variant="tonal"
                      :loading="isTargetActionLoading(row.id, 'stop')"
                      :disabled="loading || normalizeTargetStatus(row.status) === 'stopped'"
                      @click="runTargetAction(row, 'stop')"
                    >
                      Stop
                    </v-btn>
                  </div>
                </td>
              </tr>
              <tr v-if="!filteredTargets.length">
                <td colspan="8" class="text-medium-emphasis py-4 text-center">
                  No targets match current filters
                </td>
              </tr>
            </tbody>
          </v-table>
          <div class="d-flex justify-center mt-3" v-if="targetsPageCount > 1">
            <v-pagination
              v-model="pagination.targets"
              :length="targetsPageCount"
              density="comfortable"
              total-visible="7"
            />
          </div>
        </v-window-item>

        <v-window-item value="banners">
          <v-table density="compact" class="explorer-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>IP</th>
                <th>Port</th>
                <th>Proto</th>
                <th>Banner</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="row in pagedFilteredBanners" :key="row.id">
                <td>{{ row.id }}</td>
                <td>{{ row.ip }}</td>
                <td>{{ row.port }}</td>
                <td>{{ row.proto }}</td>
                <td><span class="ellipsis-cell">{{ row.response_plain || "-" }}</span></td>
              </tr>
              <tr v-if="!filteredBanners.length">
                <td colspan="5" class="text-medium-emphasis py-4 text-center">
                  No banners match current filters
                </td>
              </tr>
            </tbody>
          </v-table>
          <div class="d-flex justify-center mt-3" v-if="bannersPageCount > 1">
            <v-pagination
              v-model="pagination.banners"
              :length="bannersPageCount"
              density="comfortable"
              total-visible="7"
            />
          </div>
        </v-window-item>

        <v-window-item value="tags">
          <v-table density="compact" class="explorer-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>IP</th>
                <th>Port</th>
                <th>Proto</th>
                <th>Key</th>
                <th>Value</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="row in pagedFilteredTags" :key="row.id">
                <td>{{ row.id }}</td>
                <td>{{ row.ip }}</td>
                <td>{{ row.port }}</td>
                <td>{{ row.proto }}</td>
                <td>{{ row.key }}</td>
                <td><span class="ellipsis-cell">{{ row.value }}</span></td>
              </tr>
              <tr v-if="!filteredTags.length">
                <td colspan="6" class="text-medium-emphasis py-4 text-center">
                  No tags match current filters
                </td>
              </tr>
            </tbody>
          </v-table>
          <div class="d-flex justify-center mt-3" v-if="tagsPageCount > 1">
            <v-pagination
              v-model="pagination.tags"
              :length="tagsPageCount"
              density="comfortable"
              total-visible="7"
            />
          </div>
        </v-window-item>

        <v-window-item value="favicons">
          <v-table density="compact" class="explorer-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>IP</th>
                <th>Port</th>
                <th>Proto</th>
                <th>Preview</th>
                <th>MIME</th>
                <th>Size</th>
                <th>Hash</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="row in pagedFilteredFavicons" :key="row.id">
                <td>{{ row.id }}</td>
                <td>{{ row.ip }}</td>
                <td>{{ row.port }}</td>
                <td>{{ row.proto }}</td>
                <td>
                  <button
                    type="button"
                    class="favicon-button"
                    title="Open favicon"
                    :aria-label="`Open favicon ${row.id}`"
                    @click="openFaviconById(row.id)"
                  >
                    <img :src="faviconSrcById(row.id)" alt="favicon" class="favicon-thumb" />
                  </button>
                </td>
                <td>{{ row.mime_type }}</td>
                <td>{{ formatSize(row.size) }}</td>
                <td><span class="ellipsis-cell">{{ row.sha256 }}</span></td>
              </tr>
              <tr v-if="!filteredFavicons.length">
                <td colspan="8" class="text-medium-emphasis py-4 text-center">
                  No favicons match current filters
                </td>
              </tr>
            </tbody>
          </v-table>
          <div class="d-flex justify-center mt-3" v-if="faviconsPageCount > 1">
            <v-pagination
              v-model="pagination.favicons"
              :length="faviconsPageCount"
              density="comfortable"
              total-visible="7"
            />
          </div>
        </v-window-item>
      </v-window>

      <v-dialog v-model="intelDialog.open" max-width="1180" content-class="intel-dialog-shell">
        <v-card class="intel-dialog">
          <div class="intel-dialog__header">
            <div>
              <div class="text-overline text-primary">IP Intel</div>
              <div class="text-h6">Analysis for {{ intelDialog.ip || "-" }}</div>
              <div v-if="intelDialog.data?.generated_at" class="text-caption text-medium-emphasis">
                Generated at {{ intelDialog.data.generated_at }}
              </div>
            </div>
            <div class="intel-dialog__header-actions">
              <v-btn
                size="small"
                variant="outlined"
                prepend-icon="mdi-refresh"
                :loading="intelDialog.loading"
                :disabled="!intelDialog.ip"
                @click="refreshIpIntel"
              >
                Refresh
              </v-btn>
              <v-btn
                icon="mdi-close"
                variant="text"
                aria-label="Close intel dialog"
                title="Close"
                @click="intelDialog.open = false"
              />
            </div>
          </div>

          <div class="intel-dialog__body">
            <v-alert v-if="intelDialog.error" type="error" variant="tonal" class="mb-3">
              {{ intelDialog.error }}
            </v-alert>

            <v-progress-linear
              v-if="intelDialog.loading"
              indeterminate
              color="primary"
              height="3"
              rounded
              class="mb-3"
            />

            <template v-if="intelDialog.data">
            <v-row dense class="mb-2 intel-chip-row">
              <v-col cols="12" sm="6" md="4" lg="2">
                <v-chip class="w-100 justify-center" variant="tonal" color="info">
                  Method: {{ intelTtlPath.method || "-" }}
                </v-chip>
              </v-col>
              <v-col cols="12" sm="6" md="4" lg="2">
                <v-chip class="w-100 justify-center" variant="tonal" color="secondary">
                  Scope: {{ intelHostTarget.scope || "-" }}
                </v-chip>
              </v-col>
              <v-col cols="12" sm="6" md="4" lg="2">
                <v-chip class="w-100 justify-center" variant="tonal" color="success">
                  Open: {{ intelHostTransport.open_port_count ?? "-" }}
                </v-chip>
              </v-col>
              <v-col cols="12" sm="6" md="4" lg="2">
                <v-chip class="w-100 justify-center" variant="tonal" color="warning">
                  Filtered: {{ intelHostTransport.filtered_port_count ?? "-" }}
                </v-chip>
              </v-col>
              <v-col cols="12" sm="6" md="4" lg="2">
                <v-chip class="w-100 justify-center" variant="tonal" :color="firewallChipColor(intelHostFirewall.status)">
                  Firewall: {{ humanizeFirewall(intelHostFirewall.status) }}
                </v-chip>
              </v-col>
              <v-col cols="12" sm="6" md="4" lg="2">
                <v-chip
                  class="w-100 justify-center"
                  :color="intelDialog.data.cached ? 'secondary' : 'primary'"
                  variant="outlined"
                >
                  {{ intelDialog.data.cached ? "Cached" : "Fresh" }}
                </v-chip>
              </v-col>
            </v-row>

            <v-alert
              v-if="intelNotes.length"
              type="warning"
              variant="tonal"
              density="comfortable"
              class="mb-3"
            >
              <div v-for="note in intelNotes" :key="note">{{ note }}</div>
            </v-alert>

            <div class="text-subtitle-2 mt-3">Associated domains</div>
            <div class="d-flex flex-wrap ga-2 mt-2">
              <v-chip
                v-for="domain in intelDomains"
                :key="domain"
                size="small"
                color="primary"
                variant="tonal"
              >
                {{ domain }}
              </v-chip>
              <span v-if="!intelDomains.length" class="text-body-2 text-medium-emphasis">
                No domains discovered for this IP.
              </span>
            </div>
            <v-alert
              v-if="intelDomainHint"
              type="info"
              variant="tonal"
              density="comfortable"
              class="mt-3"
            >
              {{ intelDomainHint }}
            </v-alert>

            <v-divider class="my-4" />

            <v-row dense class="mb-4">
              <v-col cols="12" md="6" lg="3">
                <v-sheet class="intel-stat-card pa-4" rounded="xl" border>
                  <div class="text-overline">Identity</div>
                  <div class="intel-stat-value">{{ intelDialog.ip || "-" }}</div>
                  <div class="intel-kv">
                    <span>Reverse DNS</span>
                    <strong>{{ intelReverseHost || "-" }}</strong>
                  </div>
                  <div class="intel-kv">
                    <span>Protocols</span>
                    <strong>{{ joinList(intelHostTransport.protocols) }}</strong>
                  </div>
                  <div class="intel-kv">
                    <span>Geo</span>
                    <strong>{{ intelGeoSummary }}</strong>
                  </div>
                </v-sheet>
              </v-col>

              <v-col cols="12" md="6" lg="3">
                <v-sheet class="intel-stat-card pa-4" rounded="xl" border>
                  <div class="text-overline">Exposure</div>
                  <div class="intel-stat-value">{{ intelHostTransport.open_port_count ?? 0 }}</div>
                  <div class="intel-stat-label">open services observed</div>
                  <div class="intel-kv">
                    <span>Open ports</span>
                    <strong>{{ formatPortList(intelHostTransport.open_ports) }}</strong>
                  </div>
                  <div class="intel-kv">
                    <span>Filtered ports</span>
                    <strong>{{ formatPortList(intelHostTransport.filtered_ports) }}</strong>
                  </div>
                  <div class="intel-kv">
                    <span>Firewall</span>
                    <strong>{{ intelHostFirewall.summary || "-" }}</strong>
                  </div>
                </v-sheet>
              </v-col>

              <v-col cols="12" md="6" lg="3">
                <v-sheet class="intel-stat-card pa-4" rounded="xl" border>
                  <div class="text-overline">Fingerprint</div>
                  <div class="intel-stat-value">{{ joinList(intelFingerprint.services) }}</div>
                  <div class="intel-stat-label">primary services</div>
                  <div class="intel-kv">
                    <span>Products</span>
                    <strong>{{ joinList(intelFingerprint.products) }}</strong>
                  </div>
                  <div class="intel-kv">
                    <span>Runtimes</span>
                    <strong>{{ joinList(intelFingerprint.runtimes) }}</strong>
                  </div>
                  <div class="intel-kv">
                    <span>TTL hint</span>
                    <strong>{{ intelTtlOsHint }}</strong>
                  </div>
                </v-sheet>
              </v-col>

              <v-col cols="12" md="6" lg="3">
                <v-sheet class="intel-stat-card pa-4" rounded="xl" border>
                  <div class="text-overline">Metrics</div>
                  <div class="intel-stat-value">{{ formatMs(intelMetrics.application_response_ms?.avg) }}</div>
                  <div class="intel-stat-label">app response avg</div>
                  <div class="intel-kv">
                    <span>Route RTT avg</span>
                    <strong>{{ formatMs(intelMetrics.route_rtt_ms?.avg) }}</strong>
                  </div>
                  <div class="intel-kv">
                    <span>Scan RTT avg</span>
                    <strong>{{ formatMs(intelMetrics.scan_time_ms?.avg) }}</strong>
                  </div>
                  <div class="intel-kv">
                    <span>Timeout ratio</span>
                    <strong>{{ formatRatio(intelMetrics.timeout_ratio) }}</strong>
                  </div>
                </v-sheet>
              </v-col>
            </v-row>

            <div class="text-subtitle-2">Detected services</div>
            <div class="intel-table-wrap mt-2">
            <v-table density="compact" class="intel-route-table">
              <thead>
                <tr>
                  <th>Port</th>
                  <th>Proto</th>
                  <th>State</th>
                  <th>Service</th>
                  <th>Product</th>
                  <th>Version</th>
                  <th>Banner</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="row in intelHostServices" :key="`svc-${row.proto}-${row.port}`">
                  <td>{{ row.port }}</td>
                  <td>{{ row.proto || "-" }}</td>
                  <td>{{ row.state || "-" }}</td>
                  <td>{{ joinList(row.service) }}</td>
                  <td>{{ joinList(row.product) }}</td>
                  <td>{{ joinList(row.version) }}</td>
                  <td><span class="ellipsis-cell intel-ellipsis-wide">{{ row.banner_preview || "-" }}</span></td>
                </tr>
                <tr v-if="!intelHostServices.length">
                  <td colspan="7" class="text-medium-emphasis py-4 text-center">
                    No service-level rows available for this host.
                  </td>
                </tr>
              </tbody>
            </v-table>
            </div>

            <v-divider class="my-4" />

            <div class="text-subtitle-2">HTTP enumeration</div>
            <v-alert
              v-if="intelHttpSurface.errors?.length && !intelHttpResponses.length"
              type="warning"
              variant="tonal"
              density="comfortable"
              class="mb-3"
            >
              {{ intelHttpSurface.errors.join(" | ") }}
            </v-alert>
            <div class="d-flex flex-wrap ga-2 mt-2 mb-2">
              <v-chip size="small" variant="tonal" color="info">
                Ports: {{ formatPortList(intelHttpSurface.ports) }}
              </v-chip>
              <v-chip size="small" variant="tonal" color="success">
                Methods: {{ joinList(intelHttpSurface.methods) }}
              </v-chip>
              <v-chip size="small" variant="tonal" color="warning">
                Status: {{ joinList(intelHttpSurface.status_codes) }}
              </v-chip>
            </div>
            <div class="intel-table-wrap mt-2">
            <v-table density="compact" class="intel-route-table">
              <thead>
                <tr>
                  <th>Port</th>
                  <th>Scheme</th>
                  <th>Status</th>
                  <th>Server</th>
                  <th>Allow</th>
                  <th>Title / Redirect</th>
                  <th>Time</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="row in intelHttpResponses" :key="`http-${row.scheme}-${row.port}`">
                  <td>{{ row.port }}</td>
                  <td>{{ row.scheme }}</td>
                  <td>{{ row.status_code || "-" }}</td>
                  <td>{{ row.server || row.powered_by || "-" }}</td>
                  <td>{{ joinList(row.allow_methods) }}</td>
                  <td>
                    <span class="ellipsis-cell intel-ellipsis-wide">
                      {{ row.title || row.location || row.error || "-" }}
                    </span>
                  </td>
                  <td>{{ formatMs(row.response_time_ms) }}</td>
                </tr>
                <tr v-if="!intelHttpResponses.length">
                  <td colspan="7" class="text-medium-emphasis py-4 text-center">
                    No HTTP surface detected on this host.
                  </td>
                </tr>
              </tbody>
            </v-table>
            </div>

            <v-divider class="my-4" />

            <div class="text-subtitle-2">TLS analysis</div>
            <div class="d-flex flex-wrap ga-2 mt-2 mb-2">
              <v-chip size="small" variant="tonal" color="info">
                TLS ports: {{ formatPortList(intelTlsSurface.ports) }}
              </v-chip>
              <v-chip size="small" variant="tonal" color="success">
                Versions: {{ joinList(intelTlsSurface.versions) }}
              </v-chip>
              <v-chip size="small" variant="tonal" color="warning">
                Handshake avg: {{ formatMs(intelTlsSurface.handshake_ms?.avg) }}
              </v-chip>
            </div>
            <v-alert
              v-if="intelTlsSurface.errors?.length && !intelTlsCertificates.length"
              type="warning"
              variant="tonal"
              density="comfortable"
              class="mb-3"
            >
              {{ intelTlsSurface.errors.join(" | ") }}
            </v-alert>
            <div class="intel-table-wrap mt-2">
            <v-table density="compact" class="intel-route-table">
              <thead>
                <tr>
                  <th>Port</th>
                  <th>TLS</th>
                  <th>Cipher</th>
                  <th>Subject</th>
                  <th>Issuer</th>
                  <th>SAN</th>
                  <th>Expires</th>
                  <th>HS</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="row in intelTlsCertificates" :key="`tls-${row.port}-${row.subject_cn}`">
                  <td>{{ row.port }}</td>
                  <td>{{ row.tls_version || "-" }}</td>
                  <td><span class="ellipsis-cell">{{ row.cipher || "-" }}</span></td>
                  <td>{{ row.subject_cn || row.subject_org || "-" }}</td>
                  <td>{{ row.issuer_cn || row.issuer_org || "-" }}</td>
                  <td><span class="ellipsis-cell intel-ellipsis-wide">{{ joinList(row.san_dns) }}</span></td>
                  <td>{{ row.not_after || "-" }}</td>
                  <td>{{ formatMs(row.handshake_ms) }}</td>
                </tr>
                <tr v-if="!intelTlsCertificates.length">
                  <td colspan="8" class="text-medium-emphasis py-4 text-center">
                    No TLS certificates could be negotiated for this host.
                  </td>
                </tr>
              </tbody>
            </v-table>
            </div>

            <v-divider class="my-4" />

            <div class="text-subtitle-2">TTL route</div>
            <v-alert
              v-if="intelTtlError"
              type="warning"
              variant="tonal"
              density="comfortable"
              class="mb-3"
            >
              {{ intelTtlError }}
            </v-alert>
            <div class="intel-table-wrap mt-2">
            <v-table density="compact" class="intel-route-table">
              <thead>
                <tr>
                  <th>Hop</th>
                  <th>IP</th>
                  <th>Resolved</th>
                  <th>RTT</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="hop in intelRoute" :key="`hop-${hop.hop}`">
                  <td>{{ hop.hop }}</td>
                  <td>{{ hop.ip || "*" }}</td>
                  <td>{{ hop.resolved ? "yes" : "no" }}</td>
                  <td>{{ formatMs(hop.rtt_ms) }}</td>
                </tr>
                <tr v-if="!intelRoute.length">
                  <td colspan="4" class="text-medium-emphasis py-4 text-center">
                    No hop data available.
                  </td>
                </tr>
              </tbody>
            </v-table>
            </div>
          </template>
          </div>
        </v-card>
      </v-dialog>
    </DataPanel>
  </div>
</template>

<script>
import store from "../state/appStore";
import ViewHeader from "../components/ui/ViewHeader.vue";
import DataPanel from "../components/ui/DataPanel.vue";

function ipv4ToInt(ip) {
  const parts = String(ip || "").trim().split(".");
  if (parts.length !== 4) return Number.MAX_SAFE_INTEGER;
  const nums = parts.map((part) => Number(part));
  if (nums.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
    return Number.MAX_SAFE_INTEGER;
  }
  return (((nums[0] * 256 + nums[1]) * 256 + nums[2]) * 256 + nums[3]) >>> 0;
}

function compareServiceRows(a, b) {
  const ipDiff = ipv4ToInt(a.ip) - ipv4ToInt(b.ip);
  if (ipDiff !== 0) return ipDiff;
  const portDiff = Number(a.port || 0) - Number(b.port || 0);
  if (portDiff !== 0) return portDiff;
  return String(a.proto || "").localeCompare(String(b.proto || ""));
}

const FALLBACK_PROTOCOLS = ["tcp", "udp", "icmp", "sctp"];
const PAGE_SIZE = 50;
const REALTIME_AUX_REFRESH_MS = 12000;

export default {
  name: "ExplorerView",
  components: {
    ViewHeader,
    DataPanel,
  },
  data() {
    return {
      store,
      loading: false,
      error: "",
      lastUpdated: "",
      tab: "services",
      filters: {
        query: "",
        proto: "",
        state: "",
        onlyWithBanner: false,
        onlyWithFavicon: false,
      },
      targets: [],
      portsByProto: {},
      banners: [],
      tags: [],
      favicons: [],
      intelDialog: {
        open: false,
        ip: "",
        loading: false,
        error: "",
        data: null,
      },
      targetActionLoading: {
        id: null,
        action: "",
      },
      intelLoadingByIp: {},
      wsRefreshTimer: null,
      stopTableRefreshSubscription: null,
      pagination: {
        services: 1,
        targets: 1,
        banners: 1,
        tags: 1,
        favicons: 1,
      },
      lastServicesAuxReloadAt: 0,
    };
  },
  computed: {
    apiBase() {
      return this.store.state.apiBase;
    },
    portsFlat() {
      const rows = [];
      Object.keys(this.portsByProto || {}).forEach((proto) => {
        const protoRows = Array.isArray(this.portsByProto[proto]) ? this.portsByProto[proto] : [];
        protoRows.forEach((row) => {
          rows.push({
            ...row,
            proto: String((row && row.proto) || proto || "").trim().toLowerCase(),
          });
        });
      });
      return rows;
    },
    serviceRows() {
      const merged = new Map();
      const ensureRow = (ip, port, proto) => {
        const key = this.serviceKey(ip, port, proto);
        if (!merged.has(key)) {
          merged.set(key, {
            id: key,
            ip: String(ip || ""),
            port: Number(port || 0),
            proto: String(proto || "").trim().toLowerCase(),
            state: "-",
            progress: null,
            banner: "",
            tags: [],
            tags_text: "",
            favicon_id: null,
          });
        }
        return merged.get(key);
      };

      this.portsFlat.forEach((row) => {
        const item = ensureRow(row.ip, row.port, row.proto);
        item.state = String(row.state || "-");
        item.progress = row.progress;
      });

      this.banners.forEach((row) => {
        const item = ensureRow(row.ip, row.port, row.proto);
        if (!item.banner) {
          item.banner = String(row.response_plain || "");
        }
      });

      this.tags.forEach((row) => {
        const item = ensureRow(row.ip, row.port, row.proto);
        const pair = `${row.key}=${row.value}`;
        if (!item.tags.includes(pair)) {
          item.tags.push(pair);
        }
      });

      this.favicons.forEach((row) => {
        const item = ensureRow(row.ip, row.port, row.proto);
        item.favicon_id = row.id;
      });

      return Array.from(merged.values())
        .map((row) => ({
          ...row,
          tags_text: row.tags.join("; "),
        }))
        .sort(compareServiceRows);
    },
    summary() {
      const uniqueHosts = new Set(this.serviceRows.map((row) => row.ip).filter(Boolean));
      return {
        hosts: uniqueHosts.size,
        services: this.serviceRows.length,
        targets: this.targets.length,
        banners: this.banners.length,
        tags: this.tags.length,
        favicons: this.favicons.length,
      };
    },
    protoOptions() {
      const values = new Set();
      this.serviceRows.forEach((row) => values.add(String(row.proto || "").trim().toLowerCase()));
      this.targets.forEach((row) => values.add(String(row.proto || "").trim().toLowerCase()));
      return [
        { label: "All", value: "" },
        ...Array.from(values)
          .filter(Boolean)
          .sort()
          .map((value) => ({ label: value.toUpperCase(), value })),
      ];
    },
    stateOptions() {
      const values = [...new Set(this.serviceRows.map((row) => String(row.state || "").trim().toLowerCase()))]
        .filter(Boolean)
        .sort();
      return [{ label: "All", value: "" }, ...values.map((value) => ({ label: value, value }))];
    },
    intelDomains() {
      const domains = this.intelDialog?.data?.domains?.domains;
      if (!Array.isArray(domains)) return [];
      return domains;
    },
    intelSources() {
      return this.intelDialog?.data?.domains?.sources || {};
    },
    intelDomainHint() {
      if (this.intelDomains.length > 0) return "";
      const reverseData = this.intelSources?.socket_nslookup || this.intelSources?.reverse_dns || {};
      const ptrLookup = reverseData?.ptr_lookup || {};
      const ptrStatus = String(ptrLookup.status || "").trim().toLowerCase();
      const reverseError = String(reverseData.error || "").trim();
      const candidates = Array.isArray(reverseData.candidates) ? reverseData.candidates : [];
      if (candidates.length > 0) {
        return `DNS candidates found but none verified for this IP: ${candidates.join(", ")}`;
      }
      if (ptrStatus === "no_ptr") {
        return "No PTR record found for this IP in tested DNS resolvers.";
      }
      if (reverseError) {
        return `Socket DNS lookup error: ${reverseError}`;
      }
      return "No PTR/FQDN association could be validated with socket DNS lookup.";
    },
    intelTtlPath() {
      return this.intelDialog?.data?.ttl_path || {};
    },
    intelHostProfile() {
      return this.intelDialog?.data?.host_profile || {};
    },
    intelHostTarget() {
      return this.intelHostProfile?.target || {};
    },
    intelHostTransport() {
      return this.intelHostProfile?.transport || {};
    },
    intelHostApplication() {
      return this.intelHostProfile?.application || {};
    },
    intelHostServices() {
      const rows = this.intelHostTransport?.services;
      if (!Array.isArray(rows)) return [];
      return rows;
    },
    intelHostFirewall() {
      return this.intelHostTransport?.firewall || {};
    },
    intelHttpSurface() {
      return this.intelHostApplication?.http || {};
    },
    intelHttpResponses() {
      const rows = this.intelHttpSurface?.responses;
      if (!Array.isArray(rows)) return [];
      return rows;
    },
    intelTlsSurface() {
      return this.intelHostApplication?.tls || {};
    },
    intelTlsCertificates() {
      const rows = this.intelTlsSurface?.certificates;
      if (!Array.isArray(rows)) return [];
      return rows;
    },
    intelFingerprint() {
      return this.intelHostApplication?.fingerprint || {};
    },
    intelMetrics() {
      return this.intelHostProfile?.metrics || {};
    },
    intelNotes() {
      const rows = this.intelHostProfile?.notes;
      if (!Array.isArray(rows)) return [];
      return rows;
    },
    intelReverseHost() {
      return this.intelSources?.reverse_dns?.reverse_host || this.intelSources?.socket_nslookup?.reverse_host || "";
    },
    intelGeoSummary() {
      const geo = this.intelHostTarget?.geo;
      if (!geo || geo.found === false) {
        return this.intelHostTarget?.scope === "public" ? "No GeoIP match" : "Private/local scope";
      }
      const parts = [geo.area, geo.country].filter(Boolean);
      return parts.length ? parts.join(" / ") : "Mapped";
    },
    intelTtlOsHint() {
      const hint = this.intelFingerprint?.ttl_os_hint || {};
      return hint.label || "-";
    },
    intelTtlError() {
      const ttlPath = this.intelTtlPath || {};
      const method = String(ttlPath.method || "").trim().toLowerCase();
      if (method === "tcp_ttl_estimate" || method === "scan_tag_ttl_estimate") {
        return "";
      }
      const ttlError = String(ttlPath.error || "").trim();
      if (ttlError) {
        const tcpFallbackError = String(ttlPath?.tcp_fallback?.error || "").trim();
        if (ttlError.includes("raw socket permission denied")) {
          if (tcpFallbackError) {
            return `TTL route unavailable: raw socket permission denied. TCP fallback failed: ${tcpFallbackError}`;
          }
          return "TTL route unavailable: raw socket permission denied. Run backend with CAP_NET_RAW/root to enable traceroute hops.";
        }
        return `TTL route unavailable: ${ttlError}`;
      }
      const tagFallbackError = String(ttlPath?.tag_fallback?.error || "").trim();
      const hasRoute = Array.isArray(ttlPath.route) && ttlPath.route.length > 0;
      if (tagFallbackError && !hasRoute) {
        return `TTL fallback unavailable: ${tagFallbackError}`;
      }
      return "";
    },
    intelRoute() {
      const route = this.intelTtlPath?.route;
      if (!Array.isArray(route)) return [];
      return route;
    },
    filteredServices() {
      const query = String(this.filters.query || "").trim().toLowerCase();
      const proto = String(this.filters.proto || "").trim().toLowerCase();
      const state = String(this.filters.state || "").trim().toLowerCase();
      return this.serviceRows.filter((row) => {
        if (proto && String(row.proto || "").trim().toLowerCase() !== proto) return false;
        if (state && String(row.state || "").trim().toLowerCase() !== state) return false;
        if (this.filters.onlyWithBanner && !String(row.banner || "").trim()) return false;
        if (this.filters.onlyWithFavicon && !row.favicon_id) return false;
        if (!query) return true;
        const haystack = [
          row.ip,
          row.port,
          row.proto,
          row.state,
          row.banner,
          row.tags_text,
        ]
          .map((value) => String(value == null ? "" : value).toLowerCase())
          .join(" ");
        return haystack.includes(query);
      });
    },
    filteredTargets() {
      const query = String(this.filters.query || "").trim().toLowerCase();
      const proto = String(this.filters.proto || "").trim().toLowerCase();
      return this.targets.filter((row) => {
        if (proto && String(row.proto || "").trim().toLowerCase() !== proto) return false;
        if (!query) return true;
        const haystack = [
          row.id,
          row.network,
          row.type,
          row.proto,
          row.status,
          row.port_mode,
          row.port_start,
          row.port_end,
        ]
          .map((value) => String(value == null ? "" : value).toLowerCase())
          .join(" ");
        return haystack.includes(query);
      });
    },
    filteredBanners() {
      const query = String(this.filters.query || "").trim().toLowerCase();
      const proto = String(this.filters.proto || "").trim().toLowerCase();
      return this.banners.filter((row) => {
        if (proto && String(row.proto || "").trim().toLowerCase() !== proto) return false;
        if (!query) return true;
        const haystack = [
          row.id,
          row.ip,
          row.port,
          row.proto,
          row.response_plain,
        ]
          .map((value) => String(value == null ? "" : value).toLowerCase())
          .join(" ");
        return haystack.includes(query);
      });
    },
    filteredTags() {
      const query = String(this.filters.query || "").trim().toLowerCase();
      const proto = String(this.filters.proto || "").trim().toLowerCase();
      return this.tags.filter((row) => {
        if (proto && String(row.proto || "").trim().toLowerCase() !== proto) return false;
        if (!query) return true;
        const haystack = [
          row.id,
          row.ip,
          row.port,
          row.proto,
          row.key,
          row.value,
        ]
          .map((value) => String(value == null ? "" : value).toLowerCase())
          .join(" ");
        return haystack.includes(query);
      });
    },
    filteredFavicons() {
      const query = String(this.filters.query || "").trim().toLowerCase();
      const proto = String(this.filters.proto || "").trim().toLowerCase();
      return this.favicons.filter((row) => {
        if (proto && String(row.proto || "").trim().toLowerCase() !== proto) return false;
        if (!query) return true;
        const haystack = [
          row.id,
          row.ip,
          row.port,
          row.proto,
          row.icon_url,
          row.mime_type,
          row.sha256,
          row.size,
        ]
          .map((value) => String(value == null ? "" : value).toLowerCase())
          .join(" ");
        return haystack.includes(query);
      });
    },
    pagedFilteredServices() {
      return this.paginateRows("services", this.filteredServices);
    },
    servicesPageCount() {
      return this.pageCountFor(this.filteredServices.length);
    },
    pagedFilteredTargets() {
      return this.paginateRows("targets", this.filteredTargets);
    },
    targetsPageCount() {
      return this.pageCountFor(this.filteredTargets.length);
    },
    pagedFilteredBanners() {
      return this.paginateRows("banners", this.filteredBanners);
    },
    bannersPageCount() {
      return this.pageCountFor(this.filteredBanners.length);
    },
    pagedFilteredTags() {
      return this.paginateRows("tags", this.filteredTags);
    },
    tagsPageCount() {
      return this.pageCountFor(this.filteredTags.length);
    },
    pagedFilteredFavicons() {
      return this.paginateRows("favicons", this.filteredFavicons);
    },
    faviconsPageCount() {
      return this.pageCountFor(this.filteredFavicons.length);
    },
  },
  watch: {
    apiBase() {
      this.load();
    },
    tab() {
      this.ensurePageInRangeForTab(this.tab);
    },
    filters: {
      deep: true,
      handler() {
        this.resetPagination();
      },
    },
  },
  mounted() {
    this.load();
    this.stopTableRefreshSubscription = this.store.subscribeTableRefresh(
      this.handleWsRefresh
    );
  },
  beforeUnmount() {
    if (this.wsRefreshTimer) {
      clearTimeout(this.wsRefreshTimer);
      this.wsRefreshTimer = null;
    }
    if (typeof this.stopTableRefreshSubscription === "function") {
      this.stopTableRefreshSubscription();
      this.stopTableRefreshSubscription = null;
    }
  },
  methods: {
    handleWsRefresh() {
      if (this.loading) return;
      if (this.wsRefreshTimer) return;
      this.wsRefreshTimer = setTimeout(() => {
        this.wsRefreshTimer = null;
        this.refreshActiveTabRealtime();
      }, 700);
    },
    pageCountFor(totalRows) {
      const safeTotal = Number(totalRows) || 0;
      return Math.max(1, Math.ceil(safeTotal / PAGE_SIZE));
    },
    pageFor(key, totalRows) {
      const maxPages = this.pageCountFor(totalRows);
      const raw = Number(this.pagination[key] || 1);
      const safe = Number.isInteger(raw) && raw > 0 ? Math.min(raw, maxPages) : 1;
      if (safe !== raw) {
        this.pagination = { ...this.pagination, [key]: safe };
      }
      return safe;
    },
    paginateRows(key, rows) {
      const list = Array.isArray(rows) ? rows : [];
      const page = this.pageFor(key, list.length);
      const start = (page - 1) * PAGE_SIZE;
      return list.slice(start, start + PAGE_SIZE);
    },
    rowCountForTab(tabName) {
      const tab = String(tabName || "").trim().toLowerCase();
      if (tab === "targets") return this.filteredTargets.length;
      if (tab === "banners") return this.filteredBanners.length;
      if (tab === "tags") return this.filteredTags.length;
      if (tab === "favicons") return this.filteredFavicons.length;
      return this.filteredServices.length;
    },
    ensurePageInRangeForTab(tabName) {
      const tab = String(tabName || "").trim().toLowerCase();
      if (!tab) return;
      const key = tab === "services" ? "services" : tab;
      this.pageFor(key, this.rowCountForTab(tab));
    },
    resetPagination() {
      this.pagination = {
        services: 1,
        targets: 1,
        banners: 1,
        tags: 1,
        favicons: 1,
      };
    },
    applyLastUpdated() {
      this.lastUpdated = new Date().toLocaleTimeString();
    },
    fetchProtocolsWithFallback() {
      return this.store
        .fetchJsonPromise("/protocols/")
        .then((raw) => {
          const protocols = this.normalizeProtocols(raw);
          return protocols.length ? protocols : FALLBACK_PROTOCOLS;
        })
        .catch(() => FALLBACK_PROTOCOLS);
    },
    refreshPortsForProtocols(protocols) {
      const list = Array.isArray(protocols) && protocols.length ? protocols : FALLBACK_PROTOCOLS;
      return Promise.allSettled(
        list.map((proto) => this.store.fetchJsonPromise(`/ports/${proto}/`))
      ).then((responses) => {
        const mapped = {};
        list.forEach((proto, index) => {
          const result = responses[index];
          if (result && result.status === "fulfilled") {
            mapped[proto] = this.store.extractArray(result.value);
          } else {
            mapped[proto] = [];
          }
        });
        this.portsByProto = mapped;
      });
    },
    refreshTargetsOnly() {
      return this.store.fetchJsonPromise("/targets/").then((payload) => {
        this.targets = this.store.extractArray(payload);
      });
    },
    refreshBannersOnly() {
      return this.store.fetchJsonPromise("/banners/").then((payload) => {
        this.banners = this.store.extractArray(payload);
      });
    },
    refreshTagsOnly() {
      return this.store.fetchJsonPromise("/tags/").then((payload) => {
        this.tags = this.store.extractArray(payload);
      });
    },
    refreshFaviconsOnly() {
      return this.store.fetchJsonPromise("/favicons/").then((payload) => {
        this.favicons = this.store.extractArray(payload);
      });
    },
    refreshServicesRealtime() {
      const now = Date.now();
      const shouldRefreshAux = now - this.lastServicesAuxReloadAt >= REALTIME_AUX_REFRESH_MS;
      return this.fetchProtocolsWithFallback()
        .then((protocols) => this.refreshPortsForProtocols(protocols))
        .then(() => {
          if (!shouldRefreshAux) return null;
          this.lastServicesAuxReloadAt = now;
          return Promise.allSettled([
            this.refreshBannersOnly(),
            this.refreshTagsOnly(),
            this.refreshFaviconsOnly(),
          ]);
        });
    },
    refreshActiveTabRealtime() {
      let task = null;
      const currentTab = String(this.tab || "").trim().toLowerCase();
      if (currentTab === "targets") {
        task = this.refreshTargetsOnly();
      } else if (currentTab === "banners") {
        task = this.refreshBannersOnly();
      } else if (currentTab === "tags") {
        task = this.refreshTagsOnly();
      } else if (currentTab === "favicons") {
        task = this.refreshFaviconsOnly();
      } else {
        task = this.refreshServicesRealtime();
      }
      return Promise.resolve(task)
        .then(() => {
          this.applyLastUpdated();
          this.ensurePageInRangeForTab(currentTab || "services");
        })
        .catch(() => {
          // keep stale data on transient realtime failures
        });
    },
    normalizeProtocols(raw) {
      const items = this.store.extractArray(raw);
      const unique = [...new Set(items.map((item) => String(item).trim().toLowerCase()))];
      return unique.filter(Boolean);
    },
    serviceKey(ip, port, proto) {
      return `${ip}|${Number(port || 0)}|${String(proto || "").trim().toLowerCase()}`;
    },
    formatProgress(value) {
      const numeric = Number(value);
      if (!Number.isFinite(numeric)) return "-";
      return `${numeric.toFixed(1)}%`;
    },
    formatSize(value) {
      const bytes = Number(value || 0);
      if (!Number.isFinite(bytes) || bytes <= 0) return "-";
      if (bytes < 1024) return `${bytes} B`;
      return `${(bytes / 1024).toFixed(1)} KB`;
    },
    formatMs(value) {
      const numeric = Number(value);
      if (!Number.isFinite(numeric) || numeric <= 0) return "-";
      return `${numeric.toFixed(1)} ms`;
    },
    formatRatio(value) {
      const numeric = Number(value);
      if (!Number.isFinite(numeric) || numeric < 0) return "-";
      return `${(numeric * 100).toFixed(1)}%`;
    },
    joinList(values) {
      if (!Array.isArray(values) || !values.length) return "-";
      return values.filter(Boolean).join(", ");
    },
    formatPortList(values) {
      if (!Array.isArray(values) || !values.length) return "-";
      return values.join(", ");
    },
    firewallChipColor(status) {
      const normalized = String(status || "").trim().toLowerCase();
      if (normalized === "strong_filtering") return "error";
      if (normalized === "mixed_filtering") return "warning";
      if (normalized === "light_filtering") return "info";
      if (normalized === "low_filtering") return "success";
      return "secondary";
    },
    humanizeFirewall(status) {
      const normalized = String(status || "").trim().toLowerCase();
      if (!normalized) return "-";
      return normalized.replace(/_/g, " ");
    },
    normalizeTargetStatus(value) {
      const raw = String(value || "active").trim().toLowerCase();
      if (raw === "restarting") return "restarting";
      if (raw === "stopped") return "stopped";
      return "active";
    },
    isTargetActionLoading(id, action) {
      return this.targetActionLoading.id === id && this.targetActionLoading.action === action;
    },
    formatTargetPortScope(row) {
      const mode = String(row.port_mode || "preset").trim().toLowerCase();
      const start = Number(row.port_start || 0);
      const end = Number(row.port_end || 0);
      if (mode === "single" && start > 0) {
        return `single:${start}`;
      }
      if (mode === "range" && start > 0 && end > 0) {
        return `range:${start}-${end}`;
      }
      return String(row.type || "preset");
    },
    faviconSrcById(id) {
      return this.store.apiUrl(`/favicons/raw/?id=${id}`);
    },
    openFaviconById(id) {
      if (typeof window === "undefined") return;
      window.open(this.faviconSrcById(id), "_blank", "noopener,noreferrer");
    },
    isIntelLoadingForIp(ip) {
      const key = String(ip || "").trim();
      if (!key) return false;
      return Boolean(this.intelLoadingByIp[key]);
    },
    setIntelLoadingFlag(ip, value) {
      const key = String(ip || "").trim();
      if (!key) return;
      this.intelLoadingByIp = {
        ...this.intelLoadingByIp,
        [key]: Boolean(value),
      };
    },
    fetchIpIntel(ip, forceRefresh = false) {
      const targetIp = String(ip || "").trim();
      if (!targetIp) {
        return Promise.resolve();
      }
      this.intelDialog.open = true;
      this.intelDialog.ip = targetIp;
      this.intelDialog.error = "";
      this.intelDialog.loading = true;
      this.setIntelLoadingFlag(targetIp, true);

      const refreshParam = forceRefresh ? 1 : 0;
      const endpoint = `/api/ip/intel/?ip=${encodeURIComponent(targetIp)}&refresh=${refreshParam}`;
      return this.store
        .fetchJsonPromise(endpoint)
        .then((payload) => {
          this.intelDialog.data = payload || null;
          this.intelDialog.error = "";
        })
        .catch((err) => {
          this.intelDialog.data = null;
          this.intelDialog.error = err?.message || "Failed to load IP intel";
        })
        .finally(() => {
          this.intelDialog.loading = false;
          this.setIntelLoadingFlag(targetIp, false);
        });
    },
    openIpIntel(ip) {
      return this.fetchIpIntel(ip, false);
    },
    refreshIpIntel() {
      if (!this.intelDialog.ip) return Promise.resolve();
      return this.fetchIpIntel(this.intelDialog.ip, true);
    },
    clearFilters() {
      this.filters.query = "";
      this.filters.proto = "";
      this.filters.state = "";
      this.filters.onlyWithBanner = false;
      this.filters.onlyWithFavicon = false;
      this.resetPagination();
    },
    runTargetAction(row, action) {
      const targetId = Number(row && row.id);
      if (!Number.isFinite(targetId) || targetId <= 0) {
        this.error = "Invalid target id";
        return Promise.resolve();
      }
      this.error = "";
      this.targetActionLoading.id = targetId;
      this.targetActionLoading.action = action;
      return this.store
        .fetchJsonPromise("/target/action/", {
          method: "POST",
          body: JSON.stringify({
            id: targetId,
            action,
            clean_results: false,
          }),
        })
        .then(() => this.load())
        .catch((err) => {
          this.error = err.message || `Failed to ${action} target`;
        })
        .finally(() => {
          this.targetActionLoading.id = null;
          this.targetActionLoading.action = "";
        });
    },
    load() {
      this.loading = true;
      this.error = "";
      const errors = [];

      return Promise.allSettled([
        this.store.fetchJsonPromise("/targets/"),
        this.store.fetchJsonPromise("/banners/"),
        this.store.fetchJsonPromise("/tags/"),
        this.store.fetchJsonPromise("/favicons/"),
        this.store.fetchJsonPromise("/protocols/"),
      ])
        .then(([targetsRes, bannersRes, tagsRes, faviconsRes, protocolsRes]) => {
          if (targetsRes.status === "fulfilled") {
            this.targets = this.store.extractArray(targetsRes.value);
          } else {
            this.targets = [];
            errors.push(targetsRes.reason?.message || "Failed to load targets");
          }

          if (bannersRes.status === "fulfilled") {
            this.banners = this.store.extractArray(bannersRes.value);
          } else {
            this.banners = [];
            errors.push(bannersRes.reason?.message || "Failed to load banners");
          }

          if (tagsRes.status === "fulfilled") {
            this.tags = this.store.extractArray(tagsRes.value);
          } else {
            this.tags = [];
            errors.push(tagsRes.reason?.message || "Failed to load tags");
          }

          if (faviconsRes.status === "fulfilled") {
            this.favicons = this.store.extractArray(faviconsRes.value);
          } else {
            this.favicons = [];
            errors.push(faviconsRes.reason?.message || "Failed to load favicons");
          }

          let protocols = [];
          if (protocolsRes.status === "fulfilled") {
            protocols = this.normalizeProtocols(protocolsRes.value);
          } else {
            errors.push(protocolsRes.reason?.message || "Failed to load protocols");
          }

          if (!protocols.length) {
            protocols = FALLBACK_PROTOCOLS;
          }

          return Promise.allSettled(
            protocols.map((proto) => this.store.fetchJsonPromise(`/ports/${proto}/`))
          ).then((portsResponses) => {
            const mapped = {};
            protocols.forEach((proto, index) => {
              const result = portsResponses[index];
              if (result && result.status === "fulfilled") {
                mapped[proto] = this.store.extractArray(result.value);
              } else {
                mapped[proto] = [];
                errors.push(`Failed to load ports/${proto}`);
              }
            });
            this.portsByProto = mapped;
          });
        })
        .then(() => {
          this.applyLastUpdated();
          this.lastServicesAuxReloadAt = Date.now();
          this.error = errors.join(" | ");
          this.ensurePageInRangeForTab(this.tab);
        })
        .finally(() => {
          this.loading = false;
        });
    },
  },
};
</script>

<style scoped>
.explorer-table {
  border-radius: 12px;
}

.explorer-filter-action {
  display: flex;
  align-items: flex-end;
}

.explorer-clear-btn {
  width: 100%;
  min-height: 56px;
  border-radius: 12px;
}

.ellipsis-cell {
  display: inline-block;
  max-width: 420px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.intel-dialog {
  border: 1px solid rgba(106, 180, 222, 0.24);
  overflow: hidden;
  background:
    radial-gradient(circle at top right, rgba(46, 118, 190, 0.18), transparent 38%),
    linear-gradient(180deg, rgba(8, 16, 29, 0.99), rgba(5, 12, 22, 0.99));
  box-shadow: 0 28px 80px rgba(2, 7, 15, 0.62);
}

:deep(.intel-dialog-shell) {
  width: min(1180px, calc(100vw - 24px));
}

.intel-dialog__header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 12px;
  padding: 20px 24px 14px;
  border-bottom: 1px solid rgba(106, 180, 222, 0.16);
  background: linear-gradient(180deg, rgba(10, 19, 34, 0.98), rgba(10, 19, 34, 0.88));
}

.intel-dialog__header-actions {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  justify-content: flex-end;
}

.intel-dialog__body {
  padding: 18px 24px 24px;
  max-height: min(80vh, 920px);
  overflow-y: auto;
  overflow-x: hidden;
}

.intel-chip-row {
  row-gap: 8px;
}

.intel-stat-card {
  min-height: 100%;
  background:
    radial-gradient(circle at top right, rgba(67, 167, 255, 0.12), transparent 48%),
    linear-gradient(180deg, rgba(11, 20, 35, 0.9), rgba(9, 16, 28, 0.94));
  border-color: rgba(114, 166, 214, 0.22) !important;
}

.intel-stat-value {
  font-size: 1.35rem;
  font-weight: 700;
  line-height: 1.2;
  margin: 0.2rem 0;
}

.intel-stat-label {
  color: rgba(210, 223, 238, 0.72);
  font-size: 0.85rem;
  margin-bottom: 0.8rem;
}

.intel-kv {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 1rem;
  padding: 0.3rem 0;
  border-top: 1px solid rgba(124, 156, 192, 0.12);
  font-size: 0.84rem;
}

.intel-kv span {
  color: rgba(203, 216, 230, 0.65);
  flex: 0 0 34%;
}

.intel-kv strong {
  flex: 1 1 auto;
  max-width: 64%;
  text-align: right;
  font-weight: 600;
  overflow-wrap: anywhere;
  word-break: break-word;
}

.intel-table-wrap {
  overflow-x: auto;
  border: 1px solid rgba(109, 161, 206, 0.16);
  border-radius: 10px;
  background: rgba(6, 12, 22, 0.38);
}

.intel-route-table {
  border-radius: 10px;
  overflow: hidden;
}

.intel-table-wrap :deep(table) {
  min-width: 760px;
}

.intel-ellipsis-wide {
  max-width: 320px;
}

.favicon-button {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 30px;
  height: 30px;
  border: 1px solid rgba(130, 170, 200, 0.3);
  border-radius: 8px;
  background: rgba(6, 12, 22, 0.65);
  cursor: pointer;
}

.favicon-thumb {
  width: 18px;
  height: 18px;
  object-fit: contain;
}

.target-inline-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

@media (max-width: 959px) {
  .explorer-filter-action {
    align-items: stretch;
  }

  .intel-dialog__header {
    padding: 18px 16px 12px;
    flex-direction: column;
  }

  .intel-dialog__header-actions {
    width: 100%;
    justify-content: flex-end;
  }

  .intel-dialog__body {
    padding: 16px;
    max-height: min(82vh, 920px);
  }

  .intel-kv {
    display: grid;
    grid-template-columns: 1fr;
    gap: 0.25rem;
  }

  .intel-kv span,
  .intel-kv strong {
    max-width: none;
    text-align: left;
  }
}
</style>
