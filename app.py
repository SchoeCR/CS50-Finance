import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd, check_int

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # Get currrent user id
    user_ID = session["user_id"]

    # Query current user cash
    user_cash = db.execute("SELECT cash FROM users WHERE id = ?", user_ID)

    # Create user_profile list by querying stockPurchase table where username_id = userID
    user_profile = db.execute(
        "SELECT stock_symbol, stock_name, SUM(shares) as shares, price FROM stockPurchase WHERE username_id = ? GROUP BY stock_symbol", user_ID)

    # Adjust returned price for stocks to current price and
    user_worth = 0
    for x in user_profile:
        stock = lookup(x["stock_symbol"])
        x["updated_price"] = stock["price"]
        # Recalculate share holding value
        x["total_price"] = stock["price"] * x["shares"]
        user_worth += x["total_price"]

    return render_template("index.html", user_profile=user_profile, user_cash=user_cash, user_worth=user_worth)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    # User reached route via GET
    if request.method == "GET":
        return render_template("buy.html")

    # User reached route via POST
    if request.method == "POST":

        # Ensure that symbol has been entered, return apology if not
        # Declare variable for symbol
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        if not symbol:
            return apology("No stock symbol entered")
        if not shares:
            return apology("No share quantity entered")

        #validate_number(shares)
        if not check_int(shares):
            return apology("Share quantity must be whole number.", 400)
        if int(shares) <= 0:
            return apology("Shares must be 1 or greater", 400)

        # Check if stock exists, return apology if not
        # Declare variable for stock
        stock = lookup(symbol.upper())

        if stock == None:
            return apology("Sorry, that symbol does not exist")

        if stock["price"] == None:
            return apology("Sorry, a price could not be found for that stock")
        else:
            # return render_template("price.html", price = stock["price"] )

            # Determine trade value
            tradeValue = stock["price"] * int(shares)

            # Get ID of current logged in user
            userID = session["user_id"]

            # Query finance.db -> users (table) for current cash of user
            cash_db = db.execute("SELECT cash FROM users WHERE id=?", userID)
            cash = cash_db[0]["cash"]

            # Check that user has sufficient money for trade
            if cash < tradeValue:
                return apology("Sorry, you have insufficient funds")

            # Post transaction to table stockPurchase
            db.execute("INSERT INTO stockPurchase (username_id, stock_symbol, shares, price, trade_value, stock_name) VALUES(?, ?, ?, ?, ?, ?)",
                       userID, stock["symbol"], shares, stock["price"], tradeValue, stock["name"])

            # Update user available cash
            new_cash = cash - tradeValue
            db.execute("UPDATE users SET cash=? WHERE id=?", new_cash, userID)

            # Confirm successful transaction by alerting user
            flash("Stock purchase complete!")

            # Redirect user to homepage
            return redirect("/")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    # Get currrent user id
    user_ID = session["user_id"]

    # Do SELECT query of table stockPurchase where username_id matches user_id
    user_history = db.execute(
        "SELECT trade_date, stock_symbol, shares, price, trade_value, CASE WHEN shares > 0 THEN 'Purchase' WHEN shares < 0 THEN 'Sold' ELSE NULL END AS transaction_type FROM stockPurchase WHERE username_id=?", user_ID)

    return render_template("history.html", user_history=user_history)

    return apology("TODO")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    # User reached route via GET
    if request.method == "GET":
        return render_template("quote.html")

    else:
        # Declare variable for stock symbol
        symbol = request.form.get("symbol")

        # Ensure that symbol has been entered, return apology if not
        if not symbol:
            return apology("No stock symbol entered")

        stock = lookup(symbol.upper())

        if stock == None:
            return apology("Sorry, that symbol does not exist")

        else:
            return render_template("quoted.html", stock=stock)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # User reached route via GET
    if request.method == "GET":
        return render_template("register.html")

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Declare and set variables
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Ensure username is not blank
        if not username:
            return apology("must provide username", 400)

        # Ensure password is not blank
        if not password:
            return apology("must provide password", 400)

        # Ensure confirmation is not blank
        if not confirmation:
            return apology("must provide password confirmation", 400)

        # Ensure confirmation matches password
        if confirmation != password:
            return apology("passwords do not match", 400)

        hash = generate_password_hash(password)

        try:
            user_new = db.execute("INSERT INTO users (username,hash) VALUES(?,?)", username, hash)

        except:
            return apology("username already exists", 400)

        session["user_id"] = user_new

        return redirect("/")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    # User reached route via GET
    if request.method == "GET":
        # Get current user ID
        user_id = session["user_id"]
        # Query table stockPurchase to get list of...
        # distinct stock symbols associated with current user
        user_symbols = db.execute(
            "SELECT stock_symbol, stock_name FROM stockPurchase WHERE username_id = ? GROUP BY stock_symbol", user_id)
        print(user_symbols)
        # Pass in arguments to render sell.html page
        return render_template("sell.html", user_symbols=user_symbols)
    else:
        # Check a stock symbol has been selected
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("You must select a share to sell!")
        # Check that the stock exists
        stock = lookup(symbol.upper())
        if stock == None:
            return apology("Stock does not exist!")
        # Check that input into shares is a positive integer and is greater than zero
        shares = int(request.form.get("shares"))
        if shares <= 0:
            return apology("Shares quantity cannot be zero!")
        # Check that the user has greater than or equal to shares to the input in shares
        user_shares = db.execute(
            "SELECT SUM(shares) FROM stockPurchase WHERE username_id = ? AND stock_symbol = ?", session["user_id"], symbol)
        print("User shares: " + str(user_shares[0]["SUM(shares)"]))
        if user_shares[0]["SUM(shares)"] < shares:
            return apology("You do not own enough shares of this stock!")
        # Calculate value of selected quantity to sell
        sell_value = shares * stock["price"]
        # Execute INSERT query - Insert sale transaction into stockPurchase
        db.execute("INSERT INTO stockPurchase (username_id, stock_symbol, shares, price, trade_value, stock_name) VALUES (?, ?, ?, ?, ?, ?)",
                   session["user_id"], stock["symbol"], -abs(shares), stock["price"], sell_value, stock["name"])
        # Execute UPDATE query - add value stock sale to users cash balance
        # Get users current cash balance
        curr_cash = db.execute("SELECT cash FROM users WHERE id=?", session["user_id"])
        curr_cash = curr_cash[0]["cash"]
        # Add value of stock sale to users current cash balance
        new_cash = curr_cash + sell_value
        # Update user cash balance with UPDATE query
        db.execute("UPDATE users SET cash=? WHERE id=?", new_cash, session["user_id"])
        # Confirm sale and redirect user
        flash("Stock sale complete!")
        return redirect("/")


@app.route("/profile", methods=["GET"])
@login_required
def profile():
    return render_template("profile.html")


@app.route("/profile/password", methods=["GET", "POST"])
@login_required
def password():
    # if user reached route via get
    if request.method == "GET":
        return render_template("password.html")

    # if user reached route via post
    else:
        user_id = session["user_id"]
        psw_curr = request.form.get("psw_curr")
        psw_new = request.form.get("psw_new")
        psw_new_conf = request.form.get("psw_new_conf")

        # query select users table for current user hash password
        table_psw = db.execute("SELECT hash FROM users WHERE id=?", user_id)

        # check hash in table matches input in form
        if not check_password_hash(table_psw[0]["hash"], psw_curr):
            return apology("Existing password is incorrect!")
        # check that new password and confirmation match
        if not psw_new_conf == psw_new:
            return apology("Password confirmation does not match!")

        # hash new password
        hash = generate_password_hash(psw_new)
        # update table users for current user
        db.execute("UPDATE users SET hash=? WHERE id=?", hash, user_id)
        # confirm update and refresh page
        flash("Password updated")
        return render_template("password.html")


@app.route("/profile/balance", methods=["GET", "POST"])
@login_required
def balance():
    # if user reached route via get
    if request.method == "GET":
        # query select users table for current user cash balance
        user_id = session["user_id"]
        user_balance = db.execute("SELECT cash FROM users WHERE id=?", user_id)
        user_balance = user_balance[0]["cash"]

        return render_template("balance.html", user_balance=user_balance)

    # if user reached route via post
    else:
        user_id = session["user_id"]
        funds_add = float(request.form.get("funds_add"))
        current_balance = db.execute("SELECT cash FROM users WHERE id=?", user_id)
        current_balance = current_balance[0]["cash"]
        # check that funds_add is a positive number
        if funds_add < 0:
            return apology("Must be a positive number")
        # calculate new_balance
        new_balance = current_balance + funds_add
        # update balance of table users
        db.execute("UPDATE users SET cash=? WHERE id=?", new_balance, user_id)
        # confirm update and refresh page
        flash("Balance updated")
        return render_template("balance.html", user_balance=new_balance)
