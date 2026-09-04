/**
 * Phase 2: the deal room, visits, feedback, the owner's first response, the
 * reminder and digest jobs, chat inside the deal (lure detection, report,
 * owner-replied), agreement linking, verification closing the lead.
 *
 * CHAT_ENABLED is set before the app boots, because server.js reads it once
 * at import. The companion file deal-room-chat-off.test.js covers the 503.
 */

process.env.CHAT_ENABLED = 'true';

import test from 'node:test';
import assert from 'node:assert/strict';
import mongoose from 'mongoose';

import { request, withClient } from './setup/app.js';
import { stopTestDatabase, truncateAll } from './setup/db.js';
import { stopFakeProviders, clearPushBatches } from './setup/fakeProviders.js';
import {
  ownerWithSession, buyerWithSession, makeProperty, makeLead, adminWithSession, asAdmin, makeBuyer, loginAs,
} from './setup/factories.js';

import { sendVisitReminders } from '../../jobs/visitReminders.js';
import { sendOwnerWeeklyDigest } from '../../jobs/ownerWeeklyDigest.js';
import { attachAgreementToLead, ownerResponseStats } from '../../controllers/dealController.js';

let api;
const M = (name) => mongoose.model(name);
const H = 3600 * 1000;
const inHours = (n) => new Date(Date.now() + n * H).toISOString();

test.before(async () => { api = await request(); });
test.beforeEach(async () => { await truncateAll(); clearPushBatches(); });
test.after(async () => { await stopFakeProviders(); await stopTestDatabase(); });

/** Owner + buyer + property + lead, both signed in. */
async function dealFixture(leadOverrides = {}) {
  const o = await ownerWithSession(api);
  const b = await buyerWithSession(api);
  const property = await makeProperty(o.owner);
  const lead = await makeLead(property, b.buyer, leadOverrides);
  return { owner: o.owner, ownerCookies: o.cookies, buyer: b.buyer, buyerCookies: b.cookies, property, lead };
}

const get = (path, cookies) => withClient(api.get(path), { cookies });
const post = (path, cookies) => withClient(api.post(path), { cookies });
const put = (path, cookies) => withClient(api.put(path), { cookies });

// ---------------------------------------------------------------------------

test('reading a deal', async (t) => {
  await t.test('both parties see the same tracker; a third party is refused', async () => {
    const f = await dealFixture();
    const asBuyer = await get(`/api/deals/${f.lead._id}`, f.buyerCookies);
    const asOwner = await get(`/api/deals/${f.lead._id}`, f.ownerCookies);
    assert.equal(asBuyer.status, 200, JSON.stringify(asBuyer.body).slice(0, 200));
    assert.equal(asOwner.status, 200);
    assert.equal(asBuyer.body.data.role, 'buyer');
    assert.equal(asOwner.body.data.role, 'owner');
    assert.equal(asBuyer.body.data.stage, 'contacted');
    assert.equal(asBuyer.body.data.progress[0].done, true, 'the enquiry is pre-stamped');
    assert.deepEqual(asBuyer.body.data.progress.map((p) => p.key), ['contacted', 'visit_scheduled', 'visited', 'agreement', 'closed']);

    const stranger = await buyerWithSession(api);
    const refused = await get(`/api/deals/${f.lead._id}`, stranger.cookies);
    assert.equal(refused.status, 403);
    assert.equal(refused.body.code, 'NOT_A_PARTY');
  });

  await t.test('the buyer sees no owner phone until the owner engages; the owner sees the buyer contact at once', async () => {
    const f = await dealFixture();
    await M('User').updateOne({ _id: f.owner._id }, { $set: { phone: '9876500001' } });
    const before = await get(`/api/deals/${f.lead._id}`, f.buyerCookies);
    assert.equal(before.body.data.counterpart.phone, null);
    assert.equal(before.body.data.contactRevealed, false);

    const ownerView = await get(`/api/deals/${f.lead._id}`, f.ownerCookies);
    assert.equal(ownerView.body.data.counterpart.email, f.buyer.email);
    assert.equal(ownerView.body.data.contactRevealed, true);
    assert.equal(ownerView.body.data.userSnapshot.name, f.buyer.name);

    // The owner engages by proposing a visit.
    const propose = await post(`/api/deals/${f.lead._id}/visits`, f.ownerCookies).send({ scheduledAt: inHours(30) });
    assert.equal(propose.status, 201, JSON.stringify(propose.body));

    const after = await get(`/api/deals/${f.lead._id}`, f.buyerCookies);
    assert.equal(after.body.data.counterpart.phone, '9876500001');
    assert.equal(after.body.data.contactRevealed, true);
    assert.equal(after.body.data.notes, undefined, 'owner notes never reach the buyer');
  });

  await t.test('the list shows each side its deals with the next visit and who is waiting', async () => {
    const f = await dealFixture();
    const other = await makeProperty(f.owner);
    const otherBuyer = await makeBuyer();
    await makeLead(other, otherBuyer);

    const buyerList = await get('/api/deals', f.buyerCookies);
    assert.equal(buyerList.status, 200);
    assert.equal(buyerList.body.data.length, 1);
    assert.equal(buyerList.body.data[0].role, 'buyer');

    const ownerList = await get('/api/deals?role=owner', f.ownerCookies);
    assert.equal(ownerList.body.data.length, 2);
    assert.equal(ownerList.body.data.every((d) => d.awaitingOwner === true), true);
    assert.equal(ownerList.body.pagination.total, 2);

    await post(`/api/deals/${f.lead._id}/visits`, f.buyerCookies).send({ scheduledAt: inHours(48) });
    const again = await get('/api/deals?stage=visit_scheduled', f.ownerCookies);
    assert.equal(again.body.data.length, 1);
    assert.ok(again.body.data[0].nextVisit);
  });

  await t.test('a bad id is a 400, an unknown id a 404, no session a 401', async () => {
    const f = await dealFixture();
    assert.equal((await get('/api/deals/nope', f.buyerCookies)).status, 400);
    assert.equal((await get(`/api/deals/${new mongoose.Types.ObjectId()}`, f.buyerCookies)).status, 404);
    assert.equal((await get(`/api/deals/${f.lead._id}`)).status, 401);
  });
});

// ---------------------------------------------------------------------------

test('visits', async (t) => {
  await t.test('proposal validation: past, too far, and one open visit at a time', async () => {
    const f = await dealFixture();
    const url = `/api/deals/${f.lead._id}/visits`;
    assert.equal((await post(url, f.buyerCookies).send({ scheduledAt: 'garbage' })).body.code, 'INVALID_TIME');
    assert.equal((await post(url, f.buyerCookies).send({ scheduledAt: inHours(-1) })).body.code, 'TIME_IN_PAST');
    assert.equal((await post(url, f.buyerCookies).send({ scheduledAt: inHours(61 * 24) })).body.code, 'TOO_FAR_AHEAD');

    const ok = await post(url, f.buyerCookies).send({ scheduledAt: inHours(24), note: 'x'.repeat(500) });
    assert.equal(ok.status, 201);
    assert.equal(ok.body.data.note.length, 200, 'notes are clipped');
    assert.equal(ok.body.stage, 'visit_scheduled');

    const dup = await post(url, f.ownerCookies).send({ scheduledAt: inHours(30) });
    assert.equal(dup.status, 409);
    assert.equal(dup.body.code, 'VISIT_ALREADY_OPEN');
    assert.equal(dup.body.visitId, ok.body.data.id);

    // The proposer is told nothing; the counterpart is.
    const ownerNotes = await M('Notification').find({ user: f.owner._id, type: 'visit_proposed' }).lean();
    assert.equal(ownerNotes.length, 1);
    assert.equal(ownerNotes[0].data.kind, 'visit');
    assert.equal(String(ownerNotes[0].data.leadId), String(f.lead._id));
    assert.equal(await M('Notification').countDocuments({ user: f.buyer._id }), 0);
  });

  await t.test('only the other party confirms, and confirming records the owner response', async () => {
    const f = await dealFixture();
    const propose = await post(`/api/deals/${f.lead._id}/visits`, f.buyerCookies).send({ scheduledAt: inHours(24) });
    const visitId = propose.body.data.id;
    const url = `/api/deals/${f.lead._id}/visits/${visitId}`;

    const self = await put(url, f.buyerCookies).send({ action: 'confirm' });
    assert.equal(self.status, 409);
    assert.equal(self.body.code, 'OWN_PROPOSAL');

    const confirm = await put(url, f.ownerCookies).send({ action: 'confirm' });
    assert.equal(confirm.status, 200, JSON.stringify(confirm.body));
    assert.equal(confirm.body.data.status, 'confirmed');

    const lead = await M('Lead').findById(f.lead._id).lean();
    assert.ok(lead.firstOwnerResponseAt, 'confirming is the owner responding');

    const twice = await put(url, f.ownerCookies).send({ action: 'confirm' });
    assert.equal(twice.body.code, 'NOT_PROPOSED');

    const buyerNotes = await M('Notification').find({ user: f.buyer._id, type: 'visit_confirmed' }).lean();
    assert.equal(buyerNotes.length, 1);
  });

  await t.test('done is refused before the time and accepted after, then feedback is buyer-only and once', async () => {
    const f = await dealFixture();
    const propose = await post(`/api/deals/${f.lead._id}/visits`, f.ownerCookies).send({ scheduledAt: inHours(5) });
    const visitId = propose.body.data.id;
    const url = `/api/deals/${f.lead._id}/visits/${visitId}`;
    await put(url, f.buyerCookies).send({ action: 'confirm' });

    const early = await put(url, f.ownerCookies).send({ action: 'done' });
    assert.equal(early.status, 409);
    assert.equal(early.body.code, 'TOO_EARLY');

    // Move the visit into the past directly; the clock is not mockable through HTTP.
    await M('Lead').updateOne({ _id: f.lead._id, 'visits._id': visitId }, { $set: { 'visits.$.scheduledAt': new Date(Date.now() - 3 * H) } });

    const done = await put(url, f.ownerCookies).send({ action: 'done' });
    assert.equal(done.status, 200, JSON.stringify(done.body));
    assert.equal(done.body.stage, 'visited');
    const ask = await M('Notification').find({ user: f.buyer._id, type: 'visit_feedback_request' }).lean();
    assert.equal(ask.length, 1, 'the owner marking done asks the buyer how it went');

    const ownerFeedback = await post(`${url}/feedback`, f.ownerCookies).send({ feedback: 'interested' });
    assert.equal(ownerFeedback.status, 403);

    const bad = await post(`${url}/feedback`, f.buyerCookies).send({ feedback: 'meh' });
    assert.equal(bad.status, 400);

    const fb = await post(`${url}/feedback`, f.buyerCookies).send({ feedback: 'interested' });
    assert.equal(fb.status, 200, JSON.stringify(fb.body));
    assert.equal(fb.body.status, 'interested', 'the lead status follows the honest signal');

    const again = await post(`${url}/feedback`, f.buyerCookies).send({ feedback: 'thinking' });
    assert.equal(again.status, 409);
    assert.equal(again.body.code, 'FEEDBACK_GIVEN');

    const ownerNote = await M('Notification').find({ user: f.owner._id, type: 'deal_stage' }).lean();
    assert.equal(ownerNote.length, 1);
    assert.match(ownerNote[0].message, /interested/);
  });

  await t.test('feedback never moves a lead backwards or out of a terminal state', async () => {
    const past = new Date(Date.now() - 3 * H);
    const f = await dealFixture({
      status: 'negotiating',
      visits: [{ scheduledAt: past, status: 'done', proposedBy: new mongoose.Types.ObjectId() }],
    });
    const visitId = (await M('Lead').findById(f.lead._id).lean()).visits[0]._id;
    const fb = await post(`/api/deals/${f.lead._id}/visits/${visitId}/feedback`, f.buyerCookies).send({ feedback: 'thinking' });
    assert.equal(fb.status, 200);
    assert.equal(fb.body.status, 'negotiating', '"thinking" does not demote a negotiating lead');

    const g = await dealFixture({
      status: 'converted',
      visits: [{ scheduledAt: past, status: 'done', proposedBy: new mongoose.Types.ObjectId() }],
    });
    const vid = (await M('Lead').findById(g.lead._id).lean()).visits[0]._id;
    const fb2 = await post(`/api/deals/${g.lead._id}/visits/${vid}/feedback`, g.buyerCookies).send({ feedback: 'not_interested' });
    assert.equal(fb2.status, 200);
    assert.equal(fb2.body.status, 'converted', 'a closed deal is not reopened by a late tap');
  });

  await t.test('cancel is open to both sides and notifies the other; a closed deal takes no visits', async () => {
    const f = await dealFixture();
    const propose = await post(`/api/deals/${f.lead._id}/visits`, f.buyerCookies).send({ scheduledAt: inHours(24) });
    const url = `/api/deals/${f.lead._id}/visits/${propose.body.data.id}`;
    const cancel = await put(url, f.buyerCookies).send({ action: 'cancel' });
    assert.equal(cancel.status, 200);
    assert.equal(cancel.body.stage, 'contacted');
    assert.equal(await M('Notification').countDocuments({ user: f.owner._id, type: 'visit_cancelled' }), 1);
    assert.equal((await put(url, f.ownerCookies).send({ action: 'cancel' })).body.code, 'NOT_OPEN');
    assert.equal((await put(url, f.ownerCookies).send({ action: 'dance' })).status, 400);

    await M('Lead').updateOne({ _id: f.lead._id }, { $set: { status: 'converted' } });
    const closed = await post(`/api/deals/${f.lead._id}/visits`, f.buyerCookies).send({ scheduledAt: inHours(24) });
    assert.equal(closed.body.code, 'DEAL_CLOSED');
  });
});

// ---------------------------------------------------------------------------

test('the owner response figure', async (t) => {
  await t.test('status updates and contact logs count as the first response, once', async () => {
    const f = await dealFixture();
    const res = await put(`/api/leads/${f.lead._id}/status`, f.ownerCookies).send({ status: 'contacted' });
    assert.equal(res.status, 200, JSON.stringify(res.body));
    const first = (await M('Lead').findById(f.lead._id).lean()).firstOwnerResponseAt;
    assert.ok(first);
    await new Promise((r) => setTimeout(r, 20));
    await post(`/api/leads/${f.lead._id}/contact`, f.ownerCookies).send({ action: 'called' });
    const second = (await M('Lead').findById(f.lead._id).lean()).firstOwnerResponseAt;
    assert.equal(new Date(second).getTime(), new Date(first).getTime(), 'set once');
  });

  await t.test('the public listing shows a median only after three answered enquiries', async () => {
    const o = await ownerWithSession(api);
    const property = await makeProperty(o.owner, { isApproved: true });
    const hoursAgo = (n) => new Date(Date.now() - n * H);

    const seed = async (createdHoursAgo, answeredAfterHours) => {
      const buyer = await makeBuyer();
      const p = await makeProperty(o.owner);
      await M('Lead').create({
        property: p._id, propertyOwner: o.owner._id, user: buyer._id,
        userSnapshot: { name: buyer.name, email: buyer.email },
        createdAt: hoursAgo(createdHoursAgo),
        firstOwnerResponseAt: answeredAfterHours === null ? null : hoursAgo(createdHoursAgo - answeredAfterHours),
      });
    };

    await seed(100, 2);
    await seed(90, null);
    assert.deepEqual(await ownerResponseStats(o.owner._id), { responseHours: null, answered: 1 });
    let res = await withClient(api.get(`/api/properties/${property._id}`));
    assert.equal(res.status, 200);
    assert.equal(res.body.ownerStats.responseHours, null);

    await seed(80, 10);
    await seed(70, 4);
    const stats = await ownerResponseStats(o.owner._id);
    assert.equal(stats.answered, 3);
    assert.equal(stats.responseHours, 4, 'median of 2, 4, 10');
    res = await withClient(api.get(`/api/properties/${property._id}`));
    assert.equal(res.body.ownerStats.responseHours, 4);
    assert.equal(res.body.ownerStats.verified, false);
    assert.equal(res.body.owner.phone, undefined, 'the public payload still carries no contact detail');
  });
});

// ---------------------------------------------------------------------------

test('jobs', async (t) => {
  await t.test('visit reminders fire once per window, for confirmed visits only', async () => {
    const f = await dealFixture();
    const now = new Date();
    const confirmedAt = new Date(now.getTime() + 24 * H);
    const proposedAt = new Date(now.getTime() + 24 * H + 10 * 60 * 1000);
    await M('Lead').updateOne({ _id: f.lead._id }, {
      $set: {
        visits: [
          { scheduledAt: confirmedAt, status: 'confirmed', proposedBy: f.buyer._id, remindersSent: [] },
        ],
      },
    });
    const other = await makeLead(await makeProperty(f.owner), await makeBuyer(), {
      visits: [{ scheduledAt: proposedAt, status: 'proposed', proposedBy: f.owner._id, remindersSent: [] }],
    });

    const first = await sendVisitReminders({ now });
    assert.equal(first.reminders, 2, 'both parties of the confirmed visit');
    assert.equal(await M('Notification').countDocuments({ type: 'visit_reminder' }), 2);
    assert.equal(await M('Notification').countDocuments({ user: other.user, type: 'visit_reminder' }), 0, 'a mere proposal is not reminded');

    const second = await sendVisitReminders({ now });
    assert.equal(second.reminders, 0, 'idempotent within the window');

    const twoHours = new Date(confirmedAt.getTime() - 2 * H);
    const third = await sendVisitReminders({ now: twoHours });
    assert.equal(third.reminders, 2, 'the two-hour window is a separate reminder');
    const lead = await M('Lead').findById(f.lead._id).lean();
    assert.deepEqual(lead.visits[0].remindersSent.sort(), ['day_before', 'two_hours']);
  });

  await t.test('a visit nobody closed out asks the buyer once, two hours after', async () => {
    const f = await dealFixture({
      visits: [{ scheduledAt: new Date(Date.now() - 3 * H), status: 'confirmed', proposedBy: new mongoose.Types.ObjectId(), remindersSent: [] }],
    });
    const a = await sendVisitReminders({ now: new Date() });
    assert.equal(a.feedbackAsks, 1);
    const b = await sendVisitReminders({ now: new Date() });
    assert.equal(b.feedbackAsks, 0);
    assert.equal(await M('Notification').countDocuments({ user: f.buyer._id, type: 'visit_feedback_request' }), 1);
    assert.equal(await M('Notification').countDocuments({ user: f.owner._id, type: 'visit_feedback_request' }), 0);
  });

  await t.test('the weekly digest reports the delta, skips quiet owners, and sends once per week', async () => {
    const f = await dealFixture();
    await M('Property').updateOne({ _id: f.property._id }, { $set: { views: 41, isApproved: true, status: 'active' } });
    const quiet = await ownerWithSession(api);
    await makeProperty(quiet.owner, { views: 0, isApproved: true });

    const now = new Date('2026-09-07T02:30:00Z'); // Monday 08:00 IST
    const first = await sendOwnerWeeklyDigest({ now, cursor: null });
    assert.equal(first.sent, 1, 'the quiet owner gets nothing');
    assert.deepEqual(first.cursor, { week: '2026-W37' });

    const note = await M('Notification').findOne({ user: f.owner._id, type: 'owner_digest' }).lean();
    assert.ok(note, 'the active owner got a digest');
    assert.match(note.message, /41 views/);
    assert.match(note.message, /1 new enquiry/);
    assert.equal(note.data.kind, 'digest');

    const baseline = (await M('Property').findById(f.property._id).lean()).digestBaseline;
    assert.equal(baseline.views, 41);

    const again = await sendOwnerWeeklyDigest({ now, cursor: first.cursor });
    assert.equal(again.skipped, 'already-sent-this-week');

    // Next week, no new views and no new leads within the week, but the lead is still unanswered.
    const nextWeek = new Date('2026-09-14T02:30:00Z');
    const second = await sendOwnerWeeklyDigest({ now: nextWeek, cursor: first.cursor });
    assert.equal(second.sent, 1);
    const notes = await M('Notification').find({ user: f.owner._id, type: 'owner_digest' }).sort({ createdAt: 1 }).lean();
    assert.match(notes[1].message, /0 views/);
    assert.match(notes[1].message, /waiting on your reply/);
  });
});

// ---------------------------------------------------------------------------

test('chat inside the deal', async (t) => {
  async function openChat(f) {
    const res = await post(`/api/deals/${f.lead._id}/conversation`, f.buyerCookies).send({});
    assert.ok([200, 201].includes(res.status), JSON.stringify(res.body));
    return res.body.data.conversationId;
  }

  await t.test('opening the conversation is idempotent and binds it to the lead', async () => {
    const f = await dealFixture();
    const first = await post(`/api/deals/${f.lead._id}/conversation`, f.buyerCookies).send({});
    assert.equal(first.status, 201);
    const second = await post(`/api/deals/${f.lead._id}/conversation`, f.ownerCookies).send({});
    assert.equal(second.status, 200);
    assert.equal(second.body.data.conversationId, first.body.data.conversationId);
    const lead = await M('Lead').findById(f.lead._id).lean();
    assert.equal(String(lead.conversation), first.body.data.conversationId);
    const view = await get(`/api/deals/${f.lead._id}`, f.buyerCookies);
    assert.equal(view.body.data.conversation.id, first.body.data.conversationId);
    assert.equal(view.body.data.chatEnabled, true);
  });

  await t.test("the owner's first message is the response; later messages are push-only", async () => {
    const f = await dealFixture();
    const conversationId = await openChat(f);

    const hello = await post('/api/chat/message/send', f.buyerCookies).send({ conversationId, text: 'Is it available?' });
    assert.equal(hello.status, 201, JSON.stringify(hello.body));
    assert.equal(hello.body.flagged, false);
    assert.equal(await M('Notification').countDocuments({ user: f.owner._id, type: 'owner_replied' }), 0);

    const reply = await post('/api/chat/message/send', f.ownerCookies).send({ conversationId, text: 'Yes, come see it' });
    assert.equal(reply.status, 201);
    const lead = await M('Lead').findById(f.lead._id).lean();
    assert.ok(lead.firstOwnerResponseAt);
    const replied = await M('Notification').find({ user: f.buyer._id, type: 'owner_replied' }).lean();
    assert.equal(replied.length, 1);
    assert.equal(replied[0].data.kind, 'deal');

    await post('/api/chat/message/send', f.ownerCookies).send({ conversationId, text: 'Saturday works' });
    assert.equal(await M('Notification').countDocuments({ user: f.buyer._id, type: 'owner_replied' }), 1, 'only the first reply');
    assert.equal(await M('Notification').countDocuments({ user: f.buyer._id, type: 'message' }), 0, 'chat never writes in-app rows');
  });

  await t.test('a payment lure is flagged and followed by a system warning both parties can read', async () => {
    const f = await dealFixture();
    const conversationId = await openChat(f);
    const lure = await post('/api/chat/message/send', f.ownerCookies).send({ conversationId, text: 'Pay token amount 5000 on gpay to block it' });
    assert.equal(lure.status, 201);
    assert.equal(lure.body.flagged, true);
    assert.deepEqual(lure.body.message.flags, ['token_advance']);
    assert.equal(lure.body.warning.messageType, 'system');

    const thread = await get(`/api/chat/messages/${conversationId}`, f.buyerCookies);
    assert.equal(thread.status, 200);
    const texts = thread.body.messages.map((m) => m.messageType);
    assert.ok(texts.includes('system'), 'the warning is in the thread');
  });

  await t.test('the conversation preview stores the escaped text (B3)', async () => {
    const f = await dealFixture();
    const conversationId = await openChat(f);
    await post('/api/chat/message/send', f.buyerCookies).send({ conversationId, text: '<img src=x onerror=alert(1)>' });
    const conv = await M('Conversation').findById(conversationId).lean();
    assert.ok(!conv.lastMessage.text.includes('<img'), conv.lastMessage.text);
    assert.ok(conv.lastMessage.text.includes('&lt;img'));
  });

  await t.test('reporting: participants only, never your own, once per message', async () => {
    const f = await dealFixture();
    const conversationId = await openChat(f);
    const sent = await post('/api/chat/message/send', f.ownerCookies).send({ conversationId, text: 'send advance first' });
    const messageId = sent.body.message._id;

    const own = await post('/api/chat/message/report', f.ownerCookies).send({ messageId, reason: 'testing' });
    assert.equal(own.body.code, 'OWN_MESSAGE');

    const stranger = await buyerWithSession(api);
    const outside = await post('/api/chat/message/report', stranger.cookies).send({ messageId, reason: 'testing' });
    assert.equal(outside.status, 403);

    const short = await post('/api/chat/message/report', f.buyerCookies).send({ messageId, reason: 'x' });
    assert.equal(short.body.code, 'REASON_REQUIRED');

    const ok = await post('/api/chat/message/report', f.buyerCookies).send({ messageId, reason: 'Asking for money before a visit' });
    assert.equal(ok.status, 201, JSON.stringify(ok.body));
    const dup = await post('/api/chat/message/report', f.buyerCookies).send({ messageId, reason: 'again' });
    assert.equal(dup.status, 200);
    assert.equal(dup.body.duplicate, true);
    assert.equal(await M('Report').countDocuments({ message: messageId }), 1);
    const report = await M('Report').findOne({ message: messageId }).lean();
    assert.equal(report.contextType, 'message');
    assert.equal(String(report.conversation), String(conversationId));
  });
});

// ---------------------------------------------------------------------------

test('closing the loop', async (t) => {
  await t.test('an agreement attaches to the lead and moves the stage', async () => {
    const f = await dealFixture();
    const agreementId = new mongoose.Types.ObjectId();
    const lead = await attachAgreementToLead({ propertyId: f.property._id, buyerId: f.buyer._id, agreementId });
    assert.equal(lead.stage, 'agreement');
    const view = await get(`/api/deals/${f.lead._id}`, f.buyerCookies);
    assert.equal(view.body.data.stage, 'agreement');
    assert.equal(String(view.body.data.agreement.id), String(agreementId));
    assert.equal(await attachAgreementToLead({ propertyId: f.property._id, buyerId: new mongoose.Types.ObjectId(), agreementId }), null);
  });

  await t.test('admin approval of the close converts the lead and closes the deal', async () => {
    const f = await dealFixture();
    const verification = await M('TransactionVerification').create({
      property: f.property._id, owner: f.owner._id, buyer: f.buyer._id, closingType: 'sold', documentUrls: ['https://example.com/doc.pdf'],
    });
    const session = await adminWithSession(api);
    const res = await asAdmin(api.post(`/api/admin/verifications/${verification._id}/approve`), session).send({ adminNotes: 'ok' });
    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 200));

    const lead = await M('Lead').findById(f.lead._id).lean();
    assert.equal(lead.status, 'converted');
    assert.equal(lead.stage, 'closed');
    assert.equal(String(lead.verification), String(verification._id));
    assert.ok(lead.closedAt);

    const view = await get(`/api/deals/${f.lead._id}`, f.ownerCookies);
    assert.equal(view.body.data.verification.status, 'approved');
    assert.equal(view.body.data.verification.claimed, false);
    assert.equal(view.body.data.progress.every((p) => p.done), true);
  });

  await t.test('interest through the API still creates the lead the deal room reads', async () => {
    const o = await ownerWithSession(api);
    const b = await buyerWithSession(api);
    const property = await makeProperty(o.owner, { isApproved: true });
    const res = await post(`/api/properties/interested/${property._id}`, b.cookies).send({});
    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 200));
    const list = await get('/api/deals', b.cookies);
    assert.equal(list.body.data.length, 1);
    assert.equal(list.body.data[0].stage, 'contacted');
    const buyer2 = await makeBuyer();
    const cookies2 = await loginAs(api, buyer2);
    assert.equal((await get(`/api/deals/${list.body.data[0].id}`, cookies2)).status, 403);
  });
});
