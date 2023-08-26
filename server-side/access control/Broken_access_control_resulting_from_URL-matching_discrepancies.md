## Introduction
- When routing incoming requests, websites vary in how strictly the path must match a defined endpoint.
**Example** - 
they may be tolerant of inconsistent capitalization, so a request to `/ADMIN/DELETEUSER` may still be mapped to the same `/admin/deleteUser` endpoint.
- This isn't an issue in itself, but if the access control mechanism is less tolerant, it may treat these as two distinct endpoints and fail to enforce the appropriate restrictions as a result.

- Similar discrepancies can arise if developers using the Spring framework have enabled the `useSuffixPatternMatch` option. This allows paths with an arbitrary file extension to be mapped to an equivalent endpoint with no file extension. In other words, a request to `/admin/deleteUser.anything` would still match the `/admin/deleteUser` pattern.
- Prior to Spring 5.3, this option is enabled by default.
- On other systems, you may encounter discrepancies in whether `/admin/deleteUser` and `/admin/deleteUser/` are treated as a distinct endpoints. In this case, you may be able to bypass access controls simply by appending a trailing slash to the path.