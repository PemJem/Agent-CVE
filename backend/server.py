from fastapi import FastAPI, APIRouter, HTTPException
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional
import uuid
from datetime import datetime, timedelta
import asyncio
import aiohttp
from bs4 import BeautifulSoup
import re
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
import time
import json
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from jinja2 import Template

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app without a prefix
app = FastAPI()

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Initialize scheduler
scheduler = AsyncIOScheduler()

# Define Models
class CVEItem(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    cve_id: Optional[str] = None
    title: str
    description: str
    severity: Optional[str] = None
    score: Optional[float] = None
    source: str
    url: str
    published_date: datetime
    scraped_at: datetime = Field(default_factory=datetime.utcnow)

class DailySummary(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    date: datetime
    total_cves: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    top_threats: List[CVEItem]
    summary_text: str
    created_at: datetime = Field(default_factory=datetime.utcnow)

class ScrapingStatus(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    status: str
    last_run: datetime
    next_run: Optional[datetime] = None
    items_scraped: int
    errors: List[str] = []

class EmailSubscriber(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    email: EmailStr
    added_at: datetime = Field(default_factory=datetime.utcnow)
    active: bool = True

class EmailRequest(BaseModel):
    email: EmailStr

class EmailReportStatus(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    sent_at: datetime = Field(default_factory=datetime.utcnow)
    recipients_count: int
    status: str  # "sent", "failed", "partial"
    error_details: List[str] = []

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class CVEScraper:
    def __init__(self):
        self.session = None
        self.scraped_items = []
        
    async def create_session(self):
        if not self.session:
            timeout = aiohttp.ClientTimeout(total=30)
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                }
            )
    
    async def close_session(self):
        if self.session:
            await self.session.close()
            self.session = None
    
    async def scrape_cve_details(self):
        """Scrape CVE Details website"""
        try:
            await self.create_session()
            url = "https://www.cvedetails.com/vulnerability-list.php?vendor_id=0&product_id=0&version_id=0&page=1&hasexp=0&opdos=0&opec=0&opov=0&opcsrf=0&opgpriv=0&opsqli=0&opxss=0&opdirt=0&opmemc=0&ophttpr=0&opbyp=0&opfileinc=0&opginf=0&cvssscoremin=0&cvssscoremax=0&year=0&month=0&cweid=0&order=1&trc=80&sha=9e2b1d8f7a1a8b9c3f5e6d7c8a9b0c1d2e3f4a5b"
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    html = await response.text()
                    soup = BeautifulSoup(html, 'html.parser')
                    
                    # Find CVE entries
                    rows = soup.find_all('tr', {'class': ['srrowns', 'srrows']})
                    
                    for row in rows[:10]:  # Limit to top 10
                        cells = row.find_all('td')
                        if len(cells) >= 6:
                            cve_link = cells[1].find('a')
                            if cve_link:
                                cve_id = cve_link.text.strip()
                                description = cells[2].text.strip()
                                score_text = cells[3].text.strip()
                                score = float(score_text) if score_text and score_text != '-' else 0.0
                                
                                severity = 'LOW'
                                if score >= 9.0:
                                    severity = 'CRITICAL'
                                elif score >= 7.0:
                                    severity = 'HIGH'
                                elif score >= 4.0:
                                    severity = 'MEDIUM'
                                
                                item = CVEItem(
                                    cve_id=cve_id,
                                    title=f"CVE {cve_id}",
                                    description=description[:500],
                                    severity=severity,
                                    score=score,
                                    source="CVE Details",
                                    url=f"https://www.cvedetails.com{cve_link['href']}",
                                    published_date=datetime.utcnow()
                                )
                                self.scraped_items.append(item)
                                
        except Exception as e:
            logger.error(f"Error scraping CVE Details: {e}")
    
    async def scrape_hacker_news(self):
        """Scrape The Hacker News"""
        try:
            await self.create_session()
            url = "https://thehackernews.com/search/label/Vulnerability"
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    html = await response.text()
                    soup = BeautifulSoup(html, 'html.parser')
                    
                    articles = soup.find_all('article', class_='blog-post')
                    
                    for article in articles[:5]:  # Top 5 articles
                        title_elem = article.find('h2', class_='home-title')
                        if title_elem:
                            title_link = title_elem.find('a')
                            if title_link:
                                title = title_link.text.strip()
                                url = title_link['href']
                                
                                # Get description
                                desc_elem = article.find('div', class_='home-desc')
                                description = desc_elem.text.strip()[:500] if desc_elem else title
                                
                                # Determine severity from title
                                severity = 'MEDIUM'
                                if any(word in title.lower() for word in ['critical', 'severe', 'dangerous']):
                                    severity = 'HIGH'
                                elif any(word in title.lower() for word in ['vulnerability', 'exploit', 'breach']):
                                    severity = 'MEDIUM'
                                
                                item = CVEItem(
                                    title=title,
                                    description=description,
                                    severity=severity,
                                    source="The Hacker News",
                                    url=url,
                                    published_date=datetime.utcnow()
                                )
                                self.scraped_items.append(item)
                                
        except Exception as e:
            logger.error(f"Error scraping Hacker News: {e}")
    
    async def scrape_bleeping_computer(self):
        """Scrape BleepingComputer"""
        try:
            await self.create_session()
            url = "https://www.bleepingcomputer.com/news/security/"
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    html = await response.text()
                    soup = BeautifulSoup(html, 'html.parser')
                    
                    articles = soup.find_all('div', class_='bc_latest_news_text')
                    
                    for article in articles[:5]:  # Top 5 articles
                        title_elem = article.find('h4')
                        if title_elem:
                            title_link = title_elem.find('a')
                            if title_link:
                                title = title_link.text.strip()
                                url = f"https://www.bleepingcomputer.com{title_link['href']}"
                                
                                # Get description
                                desc_elem = article.find('p')
                                description = desc_elem.text.strip()[:500] if desc_elem else title
                                
                                # Determine severity
                                severity = 'MEDIUM'
                                if any(word in title.lower() for word in ['critical', 'zero-day', 'exploit']):
                                    severity = 'HIGH'
                                
                                item = CVEItem(
                                    title=title,
                                    description=description,
                                    severity=severity,
                                    source="BleepingComputer",
                                    url=url,
                                    published_date=datetime.utcnow()
                                )
                                self.scraped_items.append(item)
                                
        except Exception as e:
            logger.error(f"Error scraping BleepingComputer: {e}")
    
    async def scrape_security_week(self):
        """Scrape SecurityWeek"""
        try:
            await self.create_session()
            url = "https://www.securityweek.com/category/vulnerabilities/"
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    html = await response.text()
                    soup = BeautifulSoup(html, 'html.parser')
                    
                    articles = soup.find_all('article')
                    
                    for article in articles[:5]:  # Top 5 articles
                        title_elem = article.find('h2') or article.find('h3')
                        if title_elem:
                            title_link = title_elem.find('a')
                            if title_link:
                                title = title_link.text.strip()
                                url = title_link['href']
                                
                                # Get description
                                desc_elem = article.find('div', class_='excerpt') or article.find('p')
                                description = desc_elem.text.strip()[:500] if desc_elem else title
                                
                                severity = 'MEDIUM'
                                if any(word in title.lower() for word in ['critical', 'high-severity']):
                                    severity = 'HIGH'
                                
                                item = CVEItem(
                                    title=title,
                                    description=description,
                                    severity=severity,
                                    source="SecurityWeek",
                                    url=url,
                                    published_date=datetime.utcnow()
                                )
                                self.scraped_items.append(item)
                                
        except Exception as e:
            logger.error(f"Error scraping SecurityWeek: {e}")
    
    async def scrape_nvd_nist(self):
        """Scrape NVD NIST"""
        try:
            await self.create_session()
            url = "https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&search_type=all&isCpeNameSearch=false"
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    html = await response.text()
                    soup = BeautifulSoup(html, 'html.parser')
                    
                    # Look for vulnerability entries
                    vuln_rows = soup.find_all('tr', {'data-testid': lambda x: x and 'vuln-row' in x})
                    
                    for row in vuln_rows[:5]:  # Top 5 vulnerabilities
                        cve_elem = row.find('strong')
                        if cve_elem:
                            cve_id = cve_elem.text.strip()
                            
                            # Get description
                            desc_elem = row.find('p')
                            description = desc_elem.text.strip()[:500] if desc_elem else f"Vulnerability {cve_id}"
                            
                            # Try to find CVSS score
                            score_elem = row.find('span', {'class': 'label'})
                            score = 0.0
                            severity = 'MEDIUM'
                            
                            if score_elem:
                                score_text = score_elem.text.strip()
                                try:
                                    score = float(score_text)
                                    if score >= 9.0:
                                        severity = 'CRITICAL'
                                    elif score >= 7.0:
                                        severity = 'HIGH'
                                    elif score >= 4.0:
                                        severity = 'MEDIUM'
                                    else:
                                        severity = 'LOW'
                                except:
                                    pass
                            
                            item = CVEItem(
                                cve_id=cve_id,
                                title=f"CVE {cve_id}",
                                description=description,
                                severity=severity,
                                score=score,
                                source="NVD NIST",
                                url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                                published_date=datetime.utcnow()
                            )
                            self.scraped_items.append(item)
                            
        except Exception as e:
            logger.error(f"Error scraping NVD NIST: {e}")
    
    async def run_all_scrapers(self):
        """Run all scrapers"""
        self.scraped_items = []
        
        tasks = [
            self.scrape_cve_details(),
            self.scrape_hacker_news(),
            self.scrape_bleeping_computer(),
            self.scrape_security_week(),
            self.scrape_nvd_nist()
        ]
        
        await asyncio.gather(*tasks, return_exceptions=True)
        await self.close_session()
        
        return self.scraped_items

# Global scraper instance
scraper = CVEScraper()

async def daily_scraping_job():
    """Daily scraping job that runs at 19:00"""
    logger.info("Starting daily CVE scraping job...")
    
    try:
        # Run scrapers
        items = await scraper.run_all_scrapers()
        
        # Save items to database
        if items:
            items_dict = [item.dict() for item in items]
            await db.cve_items.insert_many(items_dict)
            
            # Generate summary
            total_cves = len(items)
            critical_count = len([i for i in items if i.severity == 'CRITICAL'])
            high_count = len([i for i in items if i.severity == 'HIGH'])
            medium_count = len([i for i in items if i.severity == 'MEDIUM'])
            low_count = len([i for i in items if i.severity == 'LOW'])
            
            # Get top threats (highest severity/score)
            top_threats = sorted(items, key=lambda x: (x.score or 0), reverse=True)[:5]
            
            # Generate summary text
            summary_text = f"""
            Dzisiejsze podsumowanie CVE ({datetime.now().strftime('%Y-%m-%d')}):
            
            📊 Statystyki:
            - Łączna liczba zagrożeń: {total_cves}
            - Krytyczne: {critical_count}
            - Wysokie: {high_count}
            - Średnie: {medium_count}
            - Niskie: {low_count}
            
            🔥 Top 5 zagrożeń:
            {chr(10).join([f"• {threat.title} ({threat.severity})" for threat in top_threats[:5]])}
            
            Źródła: CVE Details, The Hacker News, BleepingComputer, SecurityWeek, NVD NIST
            """
            
            # Save summary
            summary = DailySummary(
                date=datetime.now().replace(hour=19, minute=0, second=0, microsecond=0),
                total_cves=total_cves,
                critical_count=critical_count,
                high_count=high_count,
                medium_count=medium_count,
                low_count=low_count,
                top_threats=top_threats,
                summary_text=summary_text
            )
            
            await db.daily_summaries.insert_one(summary.dict())
            
            # Update status
            status = ScrapingStatus(
                status="completed",
                last_run=datetime.utcnow(),
                next_run=datetime.utcnow().replace(hour=19, minute=0, second=0, microsecond=0) + timedelta(days=1),
                items_scraped=len(items),
                errors=[]
            )
            
            await db.scraping_status.delete_many({})
            await db.scraping_status.insert_one(status.dict())
            
            logger.info(f"Daily scraping completed. Scraped {len(items)} items.")
        
    except Exception as e:
        logger.error(f"Error in daily scraping job: {e}")
        
        # Update status with error
        status = ScrapingStatus(
            status="error",
            last_run=datetime.utcnow(),
            next_run=datetime.utcnow().replace(hour=19, minute=0, second=0, microsecond=0) + timedelta(days=1),
            items_scraped=0,
            errors=[str(e)]
        )
        
        await db.scraping_status.delete_many({})
        await db.scraping_status.insert_one(status.dict())

# API Routes
@api_router.get("/")
async def root():
    return {"message": "CVE Agent API - Monitoring latest vulnerabilities"}

@api_router.get("/status")
async def get_scraping_status():
    """Get current scraping status"""
    status = await db.scraping_status.find_one()
    if status:
        return ScrapingStatus(**status)
    return {"status": "not_started", "message": "No scraping runs yet"}

@api_router.get("/summaries")
async def get_daily_summaries():
    """Get recent daily summaries"""
    summaries = await db.daily_summaries.find().sort("date", -1).limit(7).to_list(length=None)
    return [DailySummary(**summary) for summary in summaries]

@api_router.get("/summaries/latest")
async def get_latest_summary():
    """Get the latest daily summary"""
    summary = await db.daily_summaries.find_one(sort=[("date", -1)])
    if summary:
        return DailySummary(**summary)
    return {"message": "No summaries available yet"}

@api_router.get("/cves/recent")
async def get_recent_cves():
    """Get recent CVEs"""
    cves = await db.cve_items.find().sort("scraped_at", -1).limit(20).to_list(length=None)
    return [CVEItem(**cve) for cve in cves]

@api_router.post("/scrape/manual")
async def manual_scrape():
    """Manually trigger scraping"""
    try:
        await daily_scraping_job()
        return {"message": "Manual scraping completed successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scraping failed: {str(e)}")

@api_router.get("/cves/by-severity/{severity}")
async def get_cves_by_severity(severity: str):
    """Get CVEs by severity level"""
    cves = await db.cve_items.find({"severity": severity.upper()}).sort("scraped_at", -1).limit(20).to_list(length=None)
    return [CVEItem(**cve) for cve in cves]

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup_event():
    """Start the scheduler on app startup"""
    logger.info("Starting CVE Agent scheduler...")
    
    # Schedule daily scraping at 19:00
    scheduler.add_job(
        daily_scraping_job,
        CronTrigger(hour=19, minute=0),
        id='daily_cve_scraping',
        replace_existing=True
    )
    
    scheduler.start()
    logger.info("Scheduler started. Daily scraping scheduled for 19:00")

@app.on_event("shutdown")
async def shutdown_db_client():
    scheduler.shutdown()
    client.close()