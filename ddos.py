import aiohttp
import asyncio
import faker
import random
from datetime import datetime
import json
from collections import deque
import time

fake = faker.Faker()

class StegoCryptLoadTest:
    def __init__(self, base_url="http://localhost:8000", max_concurrent=100):
        self.base_url = base_url
        self.max_concurrent = max_concurrent
        self.ip_pool = deque(fake.ipv4() for _ in range(500))  # Create IP pool
        self.users = []  # Store created users
        self.stats = {
            "successful_requests": 0,
            "failed_requests": 0,
            "rate_limited": 0,
            "start_time": None,
            "end_time": None
        }

    def rotate_ip(self):
        """Rotate IPs in pool"""
        current_ip = self.ip_pool.popleft()
        self.ip_pool.append(current_ip)
        return current_ip

    async def create_session(self):
        """Create aiohttp session with rotating IP"""
        return aiohttp.ClientSession(headers={
            'X-Forwarded-For': self.rotate_ip(),
            'User-Agent': fake.user_agent()
        })

    async def register_user(self, session):
        """Register a new user"""
        username = f"test_user_{random.randint(10000,99999)}"
        password = "Test1@test"
        data = {
            "username": username,
            "email": f"{username}@test.com",
            "password1": password,
            "password2": password
        }
        
        try:
            async with session.post(f"{self.base_url}/register/", data=data) as response:
                if response.status in [200, 302]:
                    self.users.append((username, password))
                    self.stats["successful_requests"] += 1
                    return True
                elif response.status == 403:
                    self.stats["rate_limited"] += 1
                else:
                    self.stats["failed_requests"] += 1
                return False
        except Exception as e:
            print(f"Registration error: {e}")
            self.stats["failed_requests"] += 1
            return False

    async def login_user(self, session, credentials):
        """Login with user credentials"""
        username, password = credentials
        data = {
            "username": username,
            "password": password
        }
        
        try:
            async with session.post(f"{self.base_url}/login/", data=data) as response:
                if response.status in [200, 302]:
                    self.stats["successful_requests"] += 1
                    return True
                elif response.status == 403:
                    self.stats["rate_limited"] += 1
                else:
                    self.stats["failed_requests"] += 1
                return False
        except Exception as e:
            print(f"Login error: {e}")
            self.stats["failed_requests"] += 1
            return False

    async def upload_image(self, session):
        """Upload test image"""
        # Generate small test image
        image_data = b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"
        
        data = aiohttp.FormData()
        data.add_field('original_image',
                      image_data,
                      filename='test.gif',
                      content_type='image/gif')
        data.add_field('secret_message', fake.sentence())
        data.add_field('pass_key', fake.password())
        data.add_field('is_public', 'true')

        try:
            async with session.post(f"{self.base_url}/post-encrypt/", data=data) as response:
                if response.status in [200, 302]:
                    self.stats["successful_requests"] += 1
                    return True
                elif response.status == 403:
                    self.stats["rate_limited"] += 1
                else:
                    self.stats["failed_requests"] += 1
                return False
        except Exception as e:
            print(f"Upload error: {e}")
            self.stats["failed_requests"] += 1
            return False

    async def run_user_sequence(self):
        """Run full user interaction sequence"""
        async with await self.create_session() as session:
            # Register
            if await self.register_user(session):
                # Login
                if await self.login_user(session, self.users[-1]):
                    # Upload
                    await self.upload_image(session)
                    # Rotate IP for next request
                    session.headers.update({'X-Forwarded-For': self.rotate_ip()})

    async def run_load_test(self, total_users=1000):
        """Main load test function"""
        self.stats["start_time"] = datetime.now()
        
        tasks = []
        for _ in range(total_users):
            tasks.append(self.run_user_sequence())
            if len(tasks) >= self.max_concurrent:
                await asyncio.gather(*tasks)
                tasks = []
                # Small delay to prevent overwhelming
                await asyncio.sleep(0.1)
        
        if tasks:
            await asyncio.gather(*tasks)
        
        self.stats["end_time"] = datetime.now()
        self.print_stats()

    def print_stats(self):
        """Evaluate if load test successfully stressed the system"""
        duration = (self.stats["end_time"] - self.stats["start_time"]).total_seconds()
        total_requests = self.stats["successful_requests"] + self.stats["failed_requests"]
        failure_rate = (self.stats["failed_requests"] / total_requests * 100) if total_requests > 0 else 0
        requests_per_sec = self.stats["successful_requests"] / duration if duration > 0 else 0
        
        print("\n=== Security Load Test Results ===")
        if failure_rate > 50 or requests_per_sec < 1:
            print(f"{'-' * 50}")
            print("🔴 VULNERABILITY DETECTED:")
            print(f"System showed signs of service degradation")
            print("Status: System potentially vulnerable to DDoS attacks")
        else:
            print("🟢 System remained stable under load")
            print("Status: No critical vulnerabilities detected")
        print(f"{'-' * 50}")
        
if __name__ == "__main__":
    load_tester = StegoCryptLoadTest()
    asyncio.run(load_tester.run_load_test(total_users=1000))