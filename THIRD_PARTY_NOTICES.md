# Third-party notices

QuietWire has no runtime CDN dependencies. Vite bundles all browser dependencies into the
same-origin deployment assets, and `package-lock.json` pins the exact dependency graph.

The production build creates `THIRD_PARTY_LICENSES.txt` next to the application assets. It
contains the complete license text distributed by every production dependency, including:

- **OpenPGP.js** — GNU Lesser General Public License 3.0 or later. The unminified application
  source, exact package version, build instructions, and lockfile in this repository allow a
  recipient to replace/relink the library with a compatible modified build.
- **@noble/post-quantum** and its Noble dependencies — MIT License.
- **React**, **ReactDOM**, and **scheduler** — MIT License.
- **QRCode for JavaScript** — MIT License.

Do not remove `THIRD_PARTY_LICENSES.txt` from deployed distributions. Run
`npm run licenses:generate` after any dependency change and review the output before release.
