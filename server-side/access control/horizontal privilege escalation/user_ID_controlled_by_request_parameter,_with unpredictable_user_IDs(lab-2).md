## Introduction
- In some applications, the exploitable parameter does not have a predictable value.
**Example** - instead of an incrementing number, an application might use globally unique identifiers (GUIDs) to identify users. Here, an attacker might be unable to guess or predict the identifier for another user.

However, the GUIDs belonging to other users might be disclosed elsewhere in the application where users are referenced, such as user messages or reviews.

## Steps to solve lab-2
### Desc - user ID controlled by request parameter, with unpredictable user IDs

1. Login with given credentials.
![[access_control23.png]]

![[access_control24.png]]
Above there is our guid for user `wiener`.

2. Now, we need to find the guid for the user `carlos` and for that we need to find any post or comments where `carlos` commented or referenced, so that we can get the guid for the user `carlos`.
![[access_control25.png]]
After clicking the above link, we get the required guid.

![[access_control26.png]]

3. Now, just copy paste the guid in your query to solve the lab and submit the API key.
