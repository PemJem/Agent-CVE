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

class DailyCVETimeline(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    date: datetime
    high_severity_cves: List[CVEItem]
    new_critical_count: int
    new_high_count: int
    total_new_count: int
    created_at: datetime = Field(default_factory=datetime.utcnow)

class UserVisit(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_session: str  # Simple session tracking
    last_visit: datetime = Field(default_factory=datetime.utcnow)
    viewed_dates: List[str] = []  # List of dates user has viewed

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

# Email configuration
def get_gmail_config():
    """Get Gmail configuration from environment variables"""
    gmail_user = os.environ.get('GMAIL_USER')
    gmail_password = os.environ.get('GMAIL_APP_PASSWORD')
    
    if not gmail_user or not gmail_password:
        logger.warning("Gmail credentials not configured. Email functionality disabled.")
        return None, None
    
    return gmail_user, gmail_password

# Load HTML template
template_path = ROOT_DIR / 'templates' / 'cve_report.html'
html_template = None

try:
    with open(template_path, 'r', encoding='utf-8') as file:
        html_template = Template(file.read())
    logger.info("Email HTML template loaded successfully")
except Exception as e:
    logger.error(f"Failed to load email template: {e}")

async def send_email_report(recipients: List[str], summary_data: dict):
    """Send HTML email report to recipients"""
    gmail_user, gmail_password = get_gmail_config()
    
    if not gmail_user or not gmail_password:
        raise HTTPException(status_code=500, detail="Gmail credentials not configured")
    
    if not html_template:
        raise HTTPException(status_code=500, detail="Email template not available")
    
    try:
        # Get recent CVEs for the report
        recent_cves = await db.cve_items.find().sort("scraped_at", -1).limit(50).to_list(length=None)
        cve_items = [CVEItem(**cve) for cve in recent_cves]
        
        # Filter high severity CVEs (CVSS >= 7.0)
        high_severity_cves = [cve for cve in cve_items if cve.severity in ['CRITICAL', 'HIGH']]
        
        # Get top threats (sorted by score)
        top_threats = sorted(cve_items, key=lambda x: (x.score or 0), reverse=True)[:5]
        
        # Render HTML
        html_content = html_template.render(
            date=datetime.now(),
            total_cves=len(cve_items),
            critical_count=len([c for c in cve_items if c.severity == 'CRITICAL']),
            high_count=len([c for c in cve_items if c.severity == 'HIGH']),
            medium_count=len([c for c in cve_items if c.severity == 'MEDIUM']),
            low_count=len([c for c in cve_items if c.severity == 'LOW']),
            high_severity_cves=high_severity_cves,
            top_threats=top_threats
        )
        
        # Create email
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f"Dzienny Raport CVE - {datetime.now().strftime('%d.%m.%Y')}"
        msg['From'] = gmail_user
        msg['To'] = ', '.join(recipients)
        
        # Attach HTML content
        html_part = MIMEText(html_content, 'html', 'utf-8')
        msg.attach(html_part)
        
        # Send email
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(gmail_user, gmail_password)
            text = msg.as_string()
            server.sendmail(gmail_user, recipients, text)
        
        logger.info(f"Email report sent successfully to {len(recipients)} recipients")
        return True
        
    except Exception as e:
        logger.error(f"Failed to send email report: {e}")
        raise HTTPException(status_code=500, detail=f"Email sending failed: {str(e)}")

async def send_daily_email_report():
    """Send daily email report to all active subscribers"""
    try:
        # Get all active email subscribers
        subscribers_cursor = db.email_subscribers.find({"active": True})
        subscribers = await subscribers_cursor.to_list(length=None)
        
        if not subscribers:
            logger.info("No active email subscribers found")
            return
        
        recipient_emails = [sub['email'] for sub in subscribers]
        
        # Get latest summary data
        latest_summary = await db.daily_summaries.find_one(sort=[("date", -1)])
        
        # Send email report
        await send_email_report(recipient_emails, latest_summary or {})
        
        # Log email report status
        report_status = EmailReportStatus(
            recipients_count=len(recipient_emails),
            status="sent",
            error_details=[]
        )
        
        await db.email_reports.insert_one(report_status.dict())
        
        logger.info(f"Daily email report sent to {len(recipient_emails)} subscribers")
        
    except Exception as e:
        logger.error(f"Failed to send daily email report: {e}")
        
        # Log failed email report
        report_status = EmailReportStatus(
            recipients_count=0,
            status="failed",
            error_details=[str(e)]
        )
        
        await db.email_reports.insert_one(report_status.dict())

async def create_daily_cve_timeline(target_date: datetime = None):
    """Create daily timeline of high severity CVEs (CVSS >= 7.0)"""
    try:
        if target_date is None:
            target_date = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        
        # Define date range for the day
        start_date = target_date
        end_date = start_date + timedelta(days=1)
        
        # Get CVEs scraped during this day with CVSS >= 7.0
        high_severity_query = {
            "scraped_at": {"$gte": start_date, "$lt": end_date},
            "$or": [
                {"severity": "CRITICAL"},
                {"severity": "HIGH"},
                {"score": {"$gte": 7.0}}
            ]
        }
        
        cves_cursor = db.cve_items.find(high_severity_query).sort("score", -1)
        cves = await cves_cursor.to_list(length=None)
        cve_items = [CVEItem(**cve) for cve in cves]
        
        if not cve_items:
            logger.info(f"No high severity CVEs found for {target_date.strftime('%Y-%m-%d')}")
            return None
        
        # Count by severity
        critical_count = len([c for c in cve_items if c.severity == 'CRITICAL'])
        high_count = len([c for c in cve_items if c.severity == 'HIGH'])
        
        # Create timeline entry
        timeline = DailyCVETimeline(
            date=target_date,
            high_severity_cves=cve_items,
            new_critical_count=critical_count,
            new_high_count=high_count,
            total_new_count=len(cve_items)
        )
        
        # Check if timeline for this date already exists
        existing = await db.daily_cve_timeline.find_one({"date": target_date})
        if existing:
            # Update existing timeline
            await db.daily_cve_timeline.update_one(
                {"date": target_date},
                {"$set": timeline.dict()}
            )
            logger.info(f"Updated CVE timeline for {target_date.strftime('%Y-%m-%d')} with {len(cve_items)} high severity CVEs")
        else:
            # Insert new timeline
            await db.daily_cve_timeline.insert_one(timeline.dict())
            logger.info(f"Created CVE timeline for {target_date.strftime('%Y-%m-%d')} with {len(cve_items)} high severity CVEs")
        
        return timeline
        
    except Exception as e:
        logger.error(f"Failed to create daily CVE timeline: {e}")
        return None

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
            
            # Send daily email report
            try:
                await send_daily_email_report()
            except Exception as email_error:
                logger.error(f"Failed to send daily email report: {email_error}")
            
            # Create daily CVE timeline for high severity CVEs
            try:
                await create_daily_cve_timeline()
            except Exception as timeline_error:
                logger.error(f"Failed to create daily CVE timeline: {timeline_error}")
        
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

# Email management endpoints
@api_router.post("/emails/subscribe")
async def subscribe_email(email_request: EmailRequest):
    """Subscribe email to daily reports"""
    try:
        # Check if email already exists
        existing = await db.email_subscribers.find_one({"email": email_request.email})
        if existing:
            if existing["active"]:
                raise HTTPException(status_code=400, detail="Email już jest zapisany do newslettera")
            else:
                # Reactivate existing email
                await db.email_subscribers.update_one(
                    {"email": email_request.email},
                    {"$set": {"active": True, "added_at": datetime.utcnow()}}
                )
                return {"message": "Email został ponownie aktywowany"}
        
        # Add new email subscriber
        subscriber = EmailSubscriber(email=email_request.email)
        await db.email_subscribers.insert_one(subscriber.dict())
        
        return {"message": "Email dodany pomyślnie do listy raportów"}
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to subscribe email: {e}")
        raise HTTPException(status_code=500, detail="Błąd podczas dodawania email")

@api_router.delete("/emails/unsubscribe")
async def unsubscribe_email(email_request: EmailRequest):
    """Unsubscribe email from daily reports"""
    try:
        result = await db.email_subscribers.update_one(
            {"email": email_request.email},
            {"$set": {"active": False}}
        )
        
        if result.modified_count == 0:
            raise HTTPException(status_code=404, detail="Email nie znaleziony w bazie")
        
        return {"message": "Email usunięty z listy raportów"}
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to unsubscribe email: {e}")
        raise HTTPException(status_code=500, detail="Błąd podczas usuwania email")

@api_router.get("/emails/subscribers")
async def get_subscribers():
    """Get list of active email subscribers"""
    try:
        subscribers = await db.email_subscribers.find({"active": True}).sort("added_at", -1).to_list(length=None)
        return [EmailSubscriber(**sub) for sub in subscribers]
    except Exception as e:
        logger.error(f"Failed to get subscribers: {e}")
        raise HTTPException(status_code=500, detail="Błąd podczas pobierania listy")

@api_router.post("/emails/send-test")
async def send_test_email(email_request: EmailRequest):
    """Send test email report to specified address"""
    try:
        # Get latest summary data
        latest_summary = await db.daily_summaries.find_one(sort=[("date", -1)])
        
        # Send test email
        await send_email_report([email_request.email], latest_summary or {})
        
        return {"message": f"Test email wysłany na adres {email_request.email}"}
    
    except Exception as e:
        logger.error(f"Failed to send test email: {e}")
        raise HTTPException(status_code=500, detail=f"Błąd wysyłania test email: {str(e)}")

@api_router.post("/emails/send-manual")
async def send_manual_report():
    """Manually send email report to all subscribers"""
    try:
        await send_daily_email_report()
        return {"message": "Raport wysłany do wszystkich subskrybentów"}
    
    except Exception as e:
        logger.error(f"Failed to send manual report: {e}")
        raise HTTPException(status_code=500, detail=f"Błąd wysyłania raportu: {str(e)}")

@api_router.get("/emails/reports/status")
async def get_email_reports_status():
    """Get recent email sending status"""
    try:
        reports = await db.email_reports.find().sort("sent_at", -1).limit(10).to_list(length=None)
        return [EmailReportStatus(**report) for report in reports]
    except Exception as e:
        logger.error(f"Failed to get email reports status: {e}")
        raise HTTPException(status_code=500, detail="Błąd podczas pobierania statusu")

# Gmail configuration endpoint
@api_router.get("/emails/config/status")
async def get_email_config_status():
    """Check if Gmail configuration is available"""
    gmail_user, gmail_password = get_gmail_config()
    is_configured = bool(gmail_user and gmail_password)
    
    return {
        "configured": is_configured,
        "gmail_user": gmail_user if is_configured else None,
        "template_available": html_template is not None
    }

# CVE Timeline endpoints
@api_router.get("/cves/timeline")
async def get_cve_timeline(days: int = 30):
    """Get CVE timeline for high severity vulnerabilities (CVSS >= 7.0)"""
    try:
        # Calculate date range
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        # Get timeline entries
        timeline_cursor = db.daily_cve_timeline.find({
            "date": {"$gte": start_date, "$lte": end_date}
        }).sort("date", -1)
        
        timeline_entries = await timeline_cursor.to_list(length=None)
        
        # If no timeline entries exist, create them for recent days with data
        if not timeline_entries:
            logger.info("No timeline entries found, creating for recent days...")
            for i in range(min(days, 7)):  # Create for last 7 days max
                target_date = (end_date - timedelta(days=i)).replace(hour=0, minute=0, second=0, microsecond=0)
                timeline_entry = await create_daily_cve_timeline(target_date)
                if timeline_entry:
                    timeline_entries.append(timeline_entry.dict())
        
        return [DailyCVETimeline(**entry) for entry in timeline_entries]
    
    except Exception as e:
        logger.error(f"Failed to get CVE timeline: {e}")
        raise HTTPException(status_code=500, detail="Błąd podczas pobierania timeline")

@api_router.get("/cves/timeline/latest")
async def get_latest_cve_timeline():
    """Get latest CVE timeline entry"""
    try:
        latest = await db.daily_cve_timeline.find_one(sort=[("date", -1)])
        
        if not latest:
            # Create timeline for today
            today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
            timeline_entry = await create_daily_cve_timeline(today)
            if timeline_entry:
                return timeline_entry
            else:
                return {"message": "Brak danych o wysokich zagrożeniach dla dzisiaj"}
        
        return DailyCVETimeline(**latest)
    
    except Exception as e:
        logger.error(f"Failed to get latest CVE timeline: {e}")
        raise HTTPException(status_code=500, detail="Błąd podczas pobierania najnowszego timeline")

@api_router.post("/cves/timeline/generate")
async def generate_timeline_for_date(target_date: str = None):
    """Manually generate timeline for specific date (YYYY-MM-DD format)"""
    try:
        if target_date:
            date_obj = datetime.strptime(target_date, '%Y-%m-%d')
        else:
            date_obj = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        
        timeline_entry = await create_daily_cve_timeline(date_obj)
        
        if timeline_entry:
            return {"message": f"Timeline utworzony dla daty {date_obj.strftime('%Y-%m-%d')}", "timeline": timeline_entry}
        else:
            return {"message": f"Brak danych wysokiego ryzyka dla daty {date_obj.strftime('%Y-%m-%d')}"}
    
    except ValueError:
        raise HTTPException(status_code=400, detail="Nieprawidłowy format daty. Użyj YYYY-MM-DD")
    except Exception as e:
        logger.error(f"Failed to generate timeline: {e}")
        raise HTTPException(status_code=500, detail="Błąd podczas generowania timeline")

@api_router.get("/cves/timeline/stats")
async def get_timeline_stats():
    """Get statistics about CVE timeline data"""
    try:
        # Get total timeline entries
        total_entries = await db.daily_cve_timeline.count_documents({})
        
        # Get entries from last 7 days
        week_ago = datetime.now() - timedelta(days=7)
        recent_entries = await db.daily_cve_timeline.count_documents({
            "date": {"$gte": week_ago}
        })
        
        # Get total high severity CVEs tracked
        pipeline = [
            {"$group": {
                "_id": None,
                "total_critical": {"$sum": "$new_critical_count"},
                "total_high": {"$sum": "$new_high_count"},
                "total_cves": {"$sum": "$total_new_count"}
            }}
        ]
        
        stats_cursor = db.daily_cve_timeline.aggregate(pipeline)
        stats_result = await stats_cursor.to_list(length=1)
        
        if stats_result:
            stats = stats_result[0]
        else:
            stats = {"total_critical": 0, "total_high": 0, "total_cves": 0}
        
        return {
            "total_timeline_entries": total_entries,
            "recent_entries_7_days": recent_entries,
            "total_critical_cves": stats["total_critical"],
            "total_high_cves": stats["total_high"],
            "total_high_severity_cves": stats["total_cves"]
        }
    
    except Exception as e:
        logger.error(f"Failed to get timeline stats: {e}")
        raise HTTPException(status_code=500, detail="Błąd podczas pobierania statystyk")

# User visit tracking
@api_router.post("/user/visit")
async def track_user_visit(session_id: str = "anonymous"):
    """Track user visit for new CVE highlighting"""
    try:
        # Update or create user visit record
        visit_record = UserVisit(
            user_session=session_id,
            last_visit=datetime.utcnow()
        )
        
        await db.user_visits.update_one(
            {"user_session": session_id},
            {"$set": visit_record.dict()},
            upsert=True
        )
        
        return {"message": "Wizyta zapisana"}
    
    except Exception as e:
        logger.error(f"Failed to track user visit: {e}")
        raise HTTPException(status_code=500, detail="Błąd śledzenia wizyty")

@api_router.get("/user/visit/{session_id}")
async def get_user_last_visit(session_id: str):
    """Get user's last visit timestamp"""
    try:
        visit = await db.user_visits.find_one({"user_session": session_id})
        
        if visit:
            return UserVisit(**visit)
        else:
            return {"last_visit": None, "viewed_dates": []}
    
    except Exception as e:
        logger.error(f"Failed to get user visit: {e}")
        raise HTTPException(status_code=500, detail="Błąd pobierania wizyty")

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