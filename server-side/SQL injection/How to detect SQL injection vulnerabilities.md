## SQL injection can be detected manually by using a systematic set of tests
1. Submitting the single quote character `'` and looking for errors or other anomalies.
2. Submitting Boolean conditions such as `OR 1=1` and `OR 1=2`, and looking for differences in the application's responses.
3. Submitting payloads designed to trigger time delays when executed within a SQL query, and looking for differences in the time taken to respond.
4. Submitting OAST payloads designed to trigger an out-of-band network interaction when executed within a SQL query, and monitoring for any resulting interactions.

