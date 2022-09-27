# Clob Mate - Web Challenge Writeup

## Overview

This challenge simply gets 5 parameters as input and creates an `Order` based on them. It creates an `order_id` based on these 5 parameters and stores an `Order` object in database. It then passes this `order_id` to a browser running in private network for determining the `order_status`. If `order_status` change to `accepted`, we can get the flag.

To solve this challenge one could have many different ideas like XSS, tricking the browser to visit an unintended endpoint (because the application uses normal `base64` instead of `url_safe_base64` to create urls). But in the end the main idea of this challenge is DOM clobbering. We will explain how to exploit this vulnerability in 3 steps.

## Step0: Parameters Flow 

The starting point of processing our parameters is code snippet below:

```Python
article = escape(request.form.get('article'))
quantity = escape(request.form.get('quantity'))
username = escape(request.form.get('username'))
if username == "pilvar":
    if not ipaddress.ip_address(request.remote_addr).is_private:
        abort(403)
address = escape(request.form.get('address'))
email = escape(request.form.get('email'))
order_id = codecs.encode((article+quantity+username+address).encode('ascii'), 'base64').decode('utf-8')
...
new_order = Order(order_id=order_id, email=email, username=username, address=address, article=article, quantity=quantity, status=status)
db.session.add(new_order)
db.session.commit()
q.enqueue(visit, order_id)
```

As you see the application escapes our parameters so if an XSS exists it will become much harder. As you see `pilvar` is a special username and only hosts in private network can choose it. We first tried to bypass it with some headers like `X-Forwarded-For: 127.0.0.1` but it didn't work. Now let's take a look at `visit` function.

```Python
async def visit(order_id):
    url = f'http://web:8080/orders/{order_id}/preview'
    print("Visiting", url)
    browser = await launch({'args': ['--no-sandbox', '--disable-setuid-sandbox']})
    page = await browser.newPage()
    await page.goto(url)
    await asyncio.sleep(3)
    await browser.close()
```

This code visits `/orders/SOME_UNSAFE_BASE64/preview`. It worths mentioning that the unsafe base64 is potentialy dangerous because we can inject a subpath with a specific input which contains `/` in its base64 but it is very limited in this challenge because we should provide ascii characters and something like base64 decoded of `update/aaaa` will have multiple non-ascii characters and application will raise error with such an input. Anyhow, we'd better use `urlsafe_b64encode` for encoding inputs used in urls. Now let's take a look at the code running on `preview` endpoint.

```Python
def order(order_id):
    if order_id:
        order = Order.query.filter_by(order_id=order_id).first()
        if not order:
            abort(404)
        if ipaddress.ip_address(request.remote_addr).is_private:
            # EXECUTED ON VISITOR BROWSER BECAUSE IT IS IN PRIVATE NETWORK
            article_infos = order.article.split(":")
            article_name = article_infos[0]
            article_link = article_infos[1]
            return render_template('inspect_order.html', order_id=order.order_id, article_name=article_name, article_link=article_link, quantity=order.quantity)
        else:
            return render_template('order_status.html', status=order.status)
    else:
        return redirect("/")
```

The vulnerability resides in `inspect_order.html`. Now lets investigate what will happen in this page.

## Step1: Indentifying DOM clobbering

We don't put the complete javascript code in this page here because it is too long. It basically sends a simple request to another endpoint and fetches `username`, `address` and `email` of specified order. If `username` is `pilvar` it accept it otherwise it rejects that order.

```JS
fetch("get_user_infos").then(res => res.text()).then(txt => {
    try {
        user = JSON.parse(txt);
        order = {
            "user": {}
        };
        order.user = user;
        if (order.user.username == "pilvar") {/*ACCEPT IT*/}
        else {/*REJECT IT*/}
    } catch (err) {
        console.log("Couldn't send the data, trying again.");
        if (order.user.username == "pilvar") {/*ACCEPT IT*/}
        else {/*REJECT IT*/}
    }
})
```

If you take a closer look at this code you will identify that in `catch` block it references an `order` object which might have not be initialized. If we look at html part of this page we identify the **DOM clobbering** vulnerability:

```html
<body>
    <p id="order" name="{{ order_id }}"><b>Order ID: </b>{{ order_id }}</p>
    <p><b>Article:</b> <a id="order" name="{{ article_name }}" href="/{{ article_link }}">{{ article_name }}</a></p>
    <p id="order" name="{{ quantity }}"><b>Quantity: </b>{{ quantity }}</p>
</body>
```

As you can see three elements have the same id which is `order`. If we have such an html snippet, `window.order` will reference an `HTMLCollection` object.

<img src="https://i.imgur.com/WHOjOZL.png"
     alt="Markdown Monster icon"
     style="margin-right: 10px;" />


As [MDN](https://developer.mozilla.org/en-US/docs/Web/API/HTMLCollection) explains we can access a specific html tag by its `name` attribute in an `HTMLCollection`:

*HTMLCollection.namedItem()*

*Returns the specific node whose ID or, as a fallback, name matches the string specified by name. Matching by name is only done as a last resort, only in HTML, and only if the referenced element supports the name attribute. Returns null if no node exists by the given name.*

*An alternative to accessing collection[name] (which instead returns undefined when name does not exist). This is mostly useful for non-JavaScript DOM implementations.*

So if we set `article_name` equal to `user`, then by accessing `order.user` we get the anchor tag with `name=user`.

<img src="https://i.imgur.com/kBKH8O7.png"
     alt="Markdown Monster icon"
     style="margin-right: 10px;" />

This is the whole idea behind DOM clobbering. If `id` of two or more html tags are equal to a global variable name in javascript code and that variable had never been initialized, then accessing that variable will reference an HTMLCollection which is a collection of those tags with that specific `id` and we can access each of them by its `name` attribute in javascript.

So we now pass step 1 which is accessing `order.user` in `catch` block an we can somehow control this object.

## Step2: How to control `username`

At this point we can access `order.user` but it's not sufficient. We should be able to set a `username` for this object and control it. At first we tried to play with `name` attribute and we tried different values for it such as:

```
user.username
user/username
user[username]
user~username
user(ANY_SPECIAL_CHARACTERS)username
...
```
Unfortunately it all failed. The specification says that something like `order["user.username"]` is valid if `name=user.username` but `order.user.username` doesn't work.

Then suddenly we identified that `order.user` is referencing an anchor tag which basically stores a url and urls have different parts like host, port, path, query, ... and one of these parts is **username**. So if the anchor tag `href` attribute was something like `https://pilvar@example.com` then we could have successfully control `order.user.username` with intended value. If we set `article_link` to `/pilvar@example.com` then `href` will be `//pilvar@example.com` and browser will construct the url parts based on current scheme (which is `http`) and `order.user.username` will become `pilvar`.

<img src="https://i.imgur.com/VhJZcsf.png"
     alt="Markdown Monster icon"
     style="margin-right: 10px;" />

The complete html snippet for test:

```html
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
</head>

<body>
    <p id="order" name="order_id"><b>Order ID: </b>order_id</p>
    <p><b>Article:</b> <a id="order" name="user" href="//pilvar@example.com">article_name</a></p>
    <p id="order" name="quantity"><b>Quantity: </b>quantity</p>
</body>

</html>
```

At this point we can control `username` by DOM clobbering and the note mentioned above about url structure which is in an anchor tag. Lets request with these parameters:

<img src="https://i.imgur.com/xd26NxZ.png"
     alt="Markdown Monster icon"
     style="margin-right: 10px;" />

But again it will respond with: Order status: **rejected**

## Step3: How to trigger `catch` block

The reason is that we don't even enter the `catch` block to trigger the DOM clobbering vulnerability. We should get out of `try` block before initializing `order` because if it get initialized, the whole attack will fail and `order` will become independent of any html tag. So the only place to trigger an error and go into `catch` block is at `JSON.parse(txt)`

We took a look at any errors which this function can raise in the documentation but it wasn't helpful. In the end ranomly we thought if we give a very long input in one of the parameters the parser will explode an the error will be triggered and we enter the `catch` block. Fortunately it worked

<img src="https://i.imgur.com/6pqc68N.png"
     alt="Markdown Monster icon"
     style="margin-right: 10px;" />

<img src="https://i.imgur.com/uWavned.png"
     alt="Markdown Monster icon"
     style="margin-right: 10px;" />

As you can see with something around 50000 characters in a parameter we triggered the error and got the flag

<img src="https://i.imgur.com/Y1Emegk.png"
     alt="Markdown Monster icon"
     style="margin-right: 10px;" />
