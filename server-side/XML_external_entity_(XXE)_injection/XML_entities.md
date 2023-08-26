## What is XML?
- XML stands for "extensible markup language".
- XML is a language designed for storing and transporting data. Like HTML, XML uses a tree-like structure of tags and data.
- Unlike HTML, XML does not use predefined tags, and so tags can be given names that describe the data.
- Earlier in the web's history, XML was in vogue as a data transport format (the "X" in "AJAX" stands for "XML"). But its popularity has now declined in favor of the JSON format.

## What are XML entities?
- XML entities are like special codes used in XML documents to show specific pieces of data. Instead of using the actual data, you use these codes.
- For instance, the codes `&lt;` and `&gt;` stand for the characters `<` and `>`. These characters are important for XML tags, which help structure the data.

## What is document type definition?
- The XML Document Type Definition (DTD) is like a rulebook for XML files. It says how the XML file should be organized, what kind of data it can hold, and other details.
- This DTD is put in the optional DOCTYPE part at the beginning of the XML file.
- The DTD can be right inside the file itself (called "internal DTD"), or it can be saved in a separate place and used when needed (called "external DTD"), or it can be a mix of both.

**Example** - 
**XML Document:**
```xml
<!DOCTYPE library SYSTEM "library.dtd">
<library>
  <book>
    <title>Harry Potter and the Sorcerer's Stone</title>
    <author>J.K. Rowling</author>
    <year>1997</year>
  </book>
  <book>
    <title>The Hobbit</title>
    <author>J.R.R. Tolkien</author>
    <year>1937</year>
  </book>
</library>
```

**DTD File ("library.dtd"):**
```js
<!ELEMENT library (book+)>
<!ELEMENT book (title, author, year)>
<!ELEMENT title (#PCDATA)>
<!ELEMENT author (#PCDATA)>
<!ELEMENT year (#PCDATA)>
```
**In this example**:
- The DTD (defined in the "library.dtd" file) contains rules that define the structure of the XML document.
- The DTD states that a `library` can contain one or more `book` elements.
- Each `book` must have a `title`, an `author`, and a `year`.
- The `title`, `author`, and `year` elements contain parsed character data (`#PCDATA`).

## What are XML custom entities?
XML allows custom entities to be defined within the DTD. For example:
```js
<!DOCTYPE foo [ <!ENTITY myentity "my entity value" > ]>
```
This definition means that any usage of the entity reference `&myentity;` within the XML document will be replaced with the defined value: "`my entity value`".

## What are XML external entities?
- XML external entities are like special placeholders in XML documents that get their content from outside sources.
- When you create an external entity, you put its definition somewhere separate from the main rules (DTD) of the XML document.
- To define an external entity, you use the word "SYSTEM" and provide a web address (URL) where the actual content of the entity is located.
**Example** - 
```js
<!DOCTYPE foo [
  <!ENTITY ext SYSTEM "http://normal-website.com">
]>
```
In this case, the `ext` entity in the XML document will get its value from the web address `http://normal-website.com`.

The URL can use the `file://` protocol, and so external entities can be loaded from file. For example:
```js
<!DOCTYPE foo [ <!ENTITY ext SYSTEM "file:///path/to/file" > ]>
```
XML external entities provide the primary means by which XML external entity attacks arise.

## XML parameter entity
- Imagine an XML parameter entity as a special shortcut for writing rules in XML. It's like a quick way to tell the computer how to understand certain things in your data.
- An XML parameter entity is a way to define a placeholder or a shortcut for a piece of XML content.
- It's typically defined using a special syntax like `%entityName;`. This entity can then be used within your Document Type Definition (DTD) or other XML structures.
#### Example - 
**Suppose you have an XML file for a recipe like this:**
```xml
<recipe>
  <title>Delicious Pancakes</title>
  <ingredients>
    <ingredient>Milk</ingredient>
    <ingredient>Flour</ingredient>
    <ingredient>Eggs</ingredient>
    <!-- ... more ingredients ... -->
  </ingredients>
</recipe>
```

**You can use an XML parameter entity to define the format for ingredients, like this:**
```xml
<!ENTITY % ingredient "<ingredient>%text;</ingredient>">
```
- Here, `%ingredient;` is the XML parameter entity. `%text;` is another predefined entity that represents text content.

**Then, you can use the `%ingredient;` shortcut in your recipe:**
```xml
<!DOCTYPE recipe [
  <!ENTITY % text "CDATA">
  <!ENTITY % ingredient "<ingredient>%text;</ingredient>">
]>
<recipe>
  <title>Delicious Pancakes</title>
  <ingredients>
    &ingredient;Milk</ingredient>
    &ingredient;Flour</ingredient>
    &ingredient;Eggs</ingredient>
    <!-- ... more ingredients ... -->
  </ingredients>
</recipe>
```
- In this example, the `%ingredient;` XML parameter entity acts as a template for defining ingredient elements.
- This way, you don't need to repeat the full `<ingredient>%text;</ingredient>` structure every time you mention an ingredient.
- The parameter entity simplifies the XML and makes it more manageable.