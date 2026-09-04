import mongoose from "mongoose";

const leadSchema = new mongoose.Schema(
  {
    // Property reference
    property: { 
      type: mongoose.Schema.Types.ObjectId, 
      ref: "Property", 
      required: true 
    },
    
    // Property owner (for easy querying)
    propertyOwner: { 
      type: mongoose.Schema.Types.ObjectId, 
      ref: "User", 
      required: true 
    },
    
    // Interested user details
    user: { 
      type: mongoose.Schema.Types.ObjectId, 
      ref: "User", 
      required: true 
    },
    
    // Snapshot of user data at time of interest (in case user updates profile later)
    userSnapshot: {
      name: { type: String, required: true },
      email: { type: String, required: true },
      phone: { type: String },
      profileImage: { type: String }
    },
    
    // Property snapshot for quick display
    propertySnapshot: {
      title: { type: String },
      price: { type: Number },
      listingType: { type: String },
      city: { type: String },
      locality: { type: String },
      propertyType: { type: String },
      bhk: { type: String }
    },
    
    // Lead status
    status: { 
      type: String, 
      enum: ["new", "contacted", "interested", "negotiating", "converted", "lost"],
      default: "new"
    },
    
    // Owner notes about this lead
    notes: { type: String },
    
    // Contact history
    contactHistory: [{
      action: { type: String }, // 'called', 'emailed', 'whatsapp', 'met'
      note: { type: String },
      date: { type: Date, default: Date.now }
    }],
    
    // Track if owner has viewed this lead
    isViewed: { type: Boolean, default: false },
    viewedAt: { type: Date },
    
    // Source of lead
    source: {
      type: String,
      enum: ["website", "mobile_app", "direct"],
      default: "website"
    },

    // ------------------------------------------------------------------
    // THE DEAL SPINE (Phase 2, engine E3). Everything the deal page shows
    // hangs off this one document; there is no separate "Deal" model.
    //
    // `stage` is DERIVED (utils/dealStage.js) and cached here on write so
    // list queries can filter on it. No client sets it.
    // ------------------------------------------------------------------
    stage: {
      type: String,
      enum: ["contacted", "visit_scheduled", "visited", "agreement", "closed"],
      default: "contacted",
    },
    stageUpdatedAt: { type: Date, default: null },

    visits: [{
      scheduledAt: { type: Date, required: true },
      status: {
        type: String,
        enum: ["proposed", "confirmed", "done", "no_show", "cancelled"],
        default: "proposed",
      },
      proposedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
      confirmedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
      completedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
      /** Each party that marked the visit done. Both present = the visit milestone (Phase 3). */
      doneConfirmedBy: { type: [mongoose.Schema.Types.ObjectId], default: [] },
      milestoneAwardedAt: { type: Date, default: null },
      cancelledBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
      note: { type: String, maxlength: 200, default: "" },
      feedback: { type: String, enum: ["interested", "not_interested", "thinking", null], default: null },
      feedbackAt: { type: Date, default: null },
      /** Which reminders the job has already sent: day_before, two_hours, feedback_ask. */
      remindersSent: { type: [String], default: [] },
      createdAt: { type: Date, default: Date.now },
      updatedAt: { type: Date, default: Date.now },
    }],

    conversation: { type: mongoose.Schema.Types.ObjectId, ref: "Conversation", default: null },
    agreement: { type: mongoose.Schema.Types.ObjectId, ref: "Agreement", default: null },
    agreementAt: { type: Date, default: null },
    verification: { type: mongoose.Schema.Types.ObjectId, ref: "TransactionVerification", default: null },
    closedAt: { type: Date, default: null },

    /**
     * The first time the owner did anything on this lead after it was
     * created: replied in chat, proposed or confirmed a visit, changed the
     * status, logged a contact. Set once. The median across an owner's leads
     * is the "usually replies within" figure on their listings.
     */
    firstOwnerResponseAt: { type: Date, default: null },
  },
  { timestamps: true }
);

// Deal-room queries (Phase 2).
leadSchema.index({ user: 1, createdAt: -1 });
leadSchema.index({ "visits.status": 1, "visits.scheduledAt": 1 });
leadSchema.index({ propertyOwner: 1, firstOwnerResponseAt: 1 });

// Indexes for faster querying
leadSchema.index({ propertyOwner: 1, createdAt: -1 });
leadSchema.index({ property: 1 });
leadSchema.index({ status: 1 });
leadSchema.index({ user: 1, property: 1 }, { unique: true }); // Prevent duplicate leads

const Lead = mongoose.model("Lead", leadSchema);
export default Lead;
