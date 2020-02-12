from . import create_app
from pytz import utc
from apscheduler.schedulers.background import BackgroundScheduler
from .main import publish_policy_pools

app = create_app()

# Schedule background job to publish policies
scheduler = BackgroundScheduler(timezone=utc)
job = scheduler.add_job(publish_policy_pools, 'interval', seconds=5)
scheduler.start()

if __name__ == '__main__':
    app.run()
