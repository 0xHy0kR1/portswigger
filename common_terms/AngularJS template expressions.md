- AngularJS template expressions are a way to embed dynamic data into your web page.
- They are typically enclosed within double curly braces `{{ }}`.

#### Example - 
>Let's say you have an AngularJS app with a controller that defines a variable like this:
```js
// AngularJS controller
app.controller('MyController', function($scope) {
  $scope.message = "Hello, AngularJS!";
});
```

>**You can use the `{{ }}` notation to display this variable in your HTML template:**
```html
<!-- HTML template -->
<div ng-controller="MyController">
  <p>{{ message }}</p>
</div>
```

In this example:
- `{{ message }}` is the AngularJS template expression.
- When the page loads, AngularJS will replace `{{ message }}` with the value of the `message` variable from the controller.
- So, the rendered page will display "Hello, AngularJS!" in the `<p>` element.