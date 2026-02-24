const EVENT_TYPES = {
  DEMO_LIKE: 'demo.like',
  DEMO_DISLIKE: 'demo.dislike',
  PALETTE_CHANGE: 'builder.palette.change',
  FONT_CHANGE: 'builder.font.change',
  LAYOUT_CHANGE: 'builder.layout.change',
  TEMPLATE_CHOOSE: 'template.choose',
  BUILD_PUBLISH: 'build.publish',
  PORTFOLIO_FILTERABLE_VIEW: 'portfolio.filterable.view'
};

export class EventsEmitter {
  constructor({ workerApiUrl, fetchImpl = fetch } = {}) {
    if (!workerApiUrl) {
      throw new Error('workerApiUrl is required');
    }

    this.workerApiUrl = workerApiUrl;
    this.fetchImpl = fetchImpl;
  }

  emit(event) {
    return this.fetchImpl(this.workerApiUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(event)
    });
  }

  trackDemoPreference({ userId, demoId, liked }) {
    return this.emit({
      userId,
      type: liked ? EVENT_TYPES.DEMO_LIKE : EVENT_TYPES.DEMO_DISLIKE,
      payload: { demoId },
      timestamp: new Date().toISOString()
    });
  }

  trackBuilderChange({ userId, field, value }) {
    const typeByField = {
      palette: EVENT_TYPES.PALETTE_CHANGE,
      font: EVENT_TYPES.FONT_CHANGE,
      layout: EVENT_TYPES.LAYOUT_CHANGE
    };

    if (!typeByField[field]) {
      throw new Error(`Unsupported builder field: ${field}`);
    }

    return this.emit({
      userId,
      type: typeByField[field],
      payload: { value },
      timestamp: new Date().toISOString()
    });
  }

  trackTemplateChosen({ userId, templateId }) {
    return this.emit({
      userId,
      type: EVENT_TYPES.TEMPLATE_CHOOSE,
      payload: { templateId },
      timestamp: new Date().toISOString()
    });
  }

  trackBuildPublished({ userId, buildId }) {
    return this.emit({
      userId,
      type: EVENT_TYPES.BUILD_PUBLISH,
      payload: { buildId },
      timestamp: new Date().toISOString()
    });
  }

  trackFilterablePortfolioViewed({ userId, section = 'portfolio' }) {
    return this.emit({
      userId,
      type: EVENT_TYPES.PORTFOLIO_FILTERABLE_VIEW,
      payload: { section },
      timestamp: new Date().toISOString()
    });
  }
}

export { EVENT_TYPES };
