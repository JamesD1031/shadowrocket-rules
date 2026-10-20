# Public delivery repository

- This repository is public. Never write credentials, private exports, subscription URLs, node definitions, certificates, or logs here.
- Personal rule edits originate in the private maintenance repository. Synchronize its approved files with tools/publish_public.py.
- The scheduled workflow may update only upstream snapshots, metadata and release/routing.module after validation.
- Render only [Rule]. Never include node choices, General, Host, Script or MITM settings in the module.
- Unknown policies or rule types must fail publication rather than silently change routing.
- Preserve the local fallback FINAL policy; the module must not contain FINAL.
- Keep the checkout action pinned to an official verified commit.
