# GeoIP Seed

`getDBNIC.py` exporta aqui el catalogo GeoIP versionable del proyecto:

- `geoip_blocks.seed.jsonl.gz`
- `country_centroids.json`

`country_centroids.json` aporta centroides por pais (`ISO 3166-1 alpha-2`) para que el seed no use la coordenada del RIR como si fuera la del pais real.

Flujo esperado:

- `getDBNIC.py` es el unico proceso que regenera/actualiza estos ficheros del repo.
- `app.py` y `server.py` no descargan GeoIP ni generan datos propios de respaldo.
- al arrancar, la app lee `geoip_blocks.seed.jsonl.gz` y lo importa a `Database.db`.
- si `Database.db` no existe, se crea y se rellena desde ese seed versionado.
