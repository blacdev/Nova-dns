# Setting up Cloudflare for Nova

This guide takes you from "I have a domain name" to "Nova can give every station its own
address". You do not need to know anything about DNS. Allow about 15 minutes, plus some
waiting time while the internet catches up.

**The free Cloudflare plan is enough.** You do not need Pro, Business or Enterprise.

## What Cloudflare does here

Think of Cloudflare as the phone book for your domain. When someone opens
`kfm.yourdomain.com`, the phone book says which computer that is.

Nova needs to write in that phone book by itself:

- when a station owner claims a name, Nova adds the entry;
- when a studio's internet address changes, Nova updates it;
- when a station needs its padlock (an HTTPS certificate), Nova adds a short note that
  proves the name is yours, then removes it.

To let Nova do that, you give it two things from Cloudflare: a **Zone ID** (which domain)
and an **API token** (a key that may edit that one domain, and nothing else).

## Before you start

You need:

- a domain name you own, for example `yourdomain.com`;
- the login for the company where you bought it (the "registrar": Namecheap, GoDaddy,
  Squarespace, and so on);
- the public IP address of the machine that runs the Nova platform.

> **Is your Nova domain part of a bigger domain?** For example `radio.mycompany.com`.
> Then add the bigger one (`mycompany.com`) to Cloudflare in step 2. Everything else in
> this guide stays the same.

## Step 1: Create a Cloudflare account

1. Go to [dash.cloudflare.com/sign-up](https://dash.cloudflare.com/sign-up).
2. Enter your email address and a password, then confirm your email when Cloudflare
   writes to you.

Already have an account? Sign in and go to step 2.

## Step 2: Add your domain to Cloudflare

1. On the Cloudflare home page, click **Add a domain** (it may say **Onboard a domain**).
2. Type your domain, `yourdomain.com`, without `www` or `https://`, and continue.
3. Choose the **Free** plan.
4. Cloudflare looks up the records your domain already has and shows them. If you have a
   website or email on this domain, check that they are in the list, then continue. If
   the domain is new, the list may be empty. That is fine.
5. Cloudflare now shows you **two nameservers**. They look like
   `anna.ns.cloudflare.com` and `bob.ns.cloudflare.com`. Keep this page open.

## Step 3: Point your domain at Cloudflare

This step happens at your registrar, not at Cloudflare.

1. Sign in where you bought the domain.
2. Open the domain's settings and find **Nameservers** (sometimes under "DNS" or
   "Advanced").
3. Choose **Custom nameservers**, delete the ones that are there, and enter the two from
   Cloudflare, exactly as shown.
4. Save.

Now wait. Cloudflare emails you when the domain is **Active**. This usually takes under
an hour and can take up to a day. You can go on with step 4 while you wait, but Nova
cannot issue certificates until the domain is Active.

## Step 4: Copy your Zone ID

1. In Cloudflare, click your domain to open its **Overview** page.
2. Scroll down. In the right-hand column there is a section called **API**.
3. Under **Zone ID**, click to copy. It is 32 letters and digits, like
   `023e105f4ecef8ad9ca31a8372d0c353`.

Do not take the **Account ID** that sits next to it. They look alike.

## Step 5: Create the API token

The token is the key Nova uses. You will make one that can only edit DNS for this one
domain.

1. Open [dash.cloudflare.com/profile/api-tokens](https://dash.cloudflare.com/profile/api-tokens)
   (or click the person icon at the top right, then **My Profile**, then **API Tokens**).
2. Click **Create Token**.
3. Next to **Edit zone DNS**, click **Use template**.
4. Under **Zone Resources**, choose **Include**, then **Specific zone**, then your domain.
5. Leave everything else as it is. Click **Continue to summary**, then **Create Token**.
6. Copy the token **now**. Cloudflare shows it only once.

Treat the token like a password. Do not put it in an email or a chat. If you lose it or
it leaks, come back to this page, click **Roll** next to the token, and give Nova the new
one.

> Use an **API token**, not the **Global API Key** further down that page. The Global
> API Key can change everything in your account, and Nova does not accept it.

## Step 6: Add the platform's own addresses

Nova makes the station addresses itself. You make three by hand, once, for the platform:

| Name | Points to | What it is |
| --- | --- | --- |
| `api` | the platform machine's public IP | where Nova studios check in |
| `app` | the platform machine's public IP | this dashboard |
| `turn` | the audio relay machine's public IP | the relay for presenters' audio |

For each one:

1. In Cloudflare, open your domain, then **DNS**, then **Records**.
2. Click **Add record**.
3. **Type**: `A`. **Name**: the name from the table (just `api`, not the full address).
   **IPv4 address**: the public IP.
4. Click the orange cloud so it turns **grey** ("DNS only").
5. Save.

**The cloud must be grey.** With an orange cloud, Cloudflare stands in the middle, and
the audio relay and the platform's certificates stop working.

`./setup.sh` offers to add `api` and `app` for you, so you may only need to add `turn`.

## Step 7: Give the two values to Nova

**The easy way.** On the platform machine, run:

```
./setup.sh
```

When it asks for the DNS provider, answer `cloudflare` and paste your token. The script
finds the Zone ID by itself, tests that the token really can edit your domain, and tells
you plainly if something is wrong.

**By hand.** Put these three lines in the `.env` file, then restart:

```
DNS_PROVIDER=cloudflare
CLOUDFLARE_API_TOKEN=paste-the-token-here
CLOUDFLARE_ZONE_ID=paste-the-zone-id-here
```

```
docker compose up -d
```

## Step 8: Check that it works

1. Sign in to the dashboard as an admin and open **Admin**, then **Setup**.
2. Click **Test the Cloudflare connection**.
3. Every line should be green. If one is red, the page says what to fix.

You can run the same test from the platform machine with `./setup.sh check`.

Then try it for real: claim a station name in the dashboard and enter its access code in
Nova. Within a minute you should see a new record for that name under **DNS**, then
**Records** in Cloudflare.

## Things you should leave alone

- **The station records.** Nova adds, changes and removes them. If you edit one by hand,
  Nova puts it back the next time the studio checks in.
- **Records that start with `_acme-challenge`.** They appear for a minute while a
  certificate is issued and then go away.
- **A `*` (wildcard) record.** Please do not add one. It would make every unclaimed name
  look like it exists.

## If something goes wrong

| What you see | What it usually means | What to do |
| --- | --- | --- |
| "Cloudflare did not accept the token" | The token was copied incompletely, deleted, or is the Global API Key | Create a new token (step 5) and paste all of it |
| "The token may not use this domain" | The token is for another domain, or the Zone ID is another domain's | In step 5 choose your domain under **Specific zone**; re-copy the Zone ID (step 4) |
| "The token can read but not change records" | The token was made with **Read** instead of **Edit** | Create a new token from the **Edit zone DNS** template |
| "Cloudflare does not know this Zone ID" | You copied the Account ID, or part of the Zone ID | Copy the **Zone ID** again (step 4) |
| "The domain is not active at Cloudflare yet" | The nameservers have not changed yet | Check step 3 at your registrar, then wait |
| A station's certificate stays "pending" | The domain is not Active yet, or it has a CAA record that forbids Let's Encrypt | Under **DNS**, **Records**, look for records of type `CAA`. If there are any, add one that allows `letsencrypt.org` |
| The dashboard or the audio relay cannot be reached | The cloud next to `api`, `app` or `turn` is orange | Click it so it turns grey (step 6) |
| Cloudflare refuses to add more records | The free plan has a limit on records per domain (200 for newly added domains) | Each station uses one record. Upgrade the plan at Cloudflare, or remove records you do not use |

Cloudflare changes the look of its pages from time to time. If a button is not exactly
where this guide says, look for the same words nearby.
