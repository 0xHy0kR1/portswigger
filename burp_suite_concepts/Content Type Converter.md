This extension converts data submitted within requests between various common formats:
- JSON To XML
- XML to JSON
- Body parameters to JSON
- Body parameters to XML

This is useful for discovering vulnerabilities that can only be found by converting the content type of a request. For example, if an original request submits data using JSON, we can attempt to convert the data to XML, to see if the application accepts data in XML form. If so, we can then look for vulnerabilities like XXE injection which would not arise in the context of the original JSON endpoint. It might also be possible to find vulnerabilities behind web application firewalls or other filters that assume the incoming data is in a specific format, while the application tolerates data in other formats.