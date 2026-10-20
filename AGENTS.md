# Public delivery repository

- This repository is public. Never write credentials, private exports, subscription URLs, node definitions, certificates, or logs here.
- Personal rule edits originate in the private maintenance repository. Synchronize its approved files with tools/publish_public.py.
- The scheduled workflow may update only upstream snapshots, metadata and the release directory after validation.
- Render only [Rule]. Never include node choices, General, Host, Script or MITM settings in the module.
- Unknown policies or rule types must fail publication rather than silently change routing.
- Preserve the local fallback FINAL policy; the module must not contain FINAL.
- Keep the checkout action pinned to an official verified commit.

- Preserve match order and policy when bundling. Keep content-addressed old bundles available for cached modules.
- Chinese remarks do not replace URL titles in the tested native client. Keep the readable classification catalog current.
