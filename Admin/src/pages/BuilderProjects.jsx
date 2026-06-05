import React, { useState, useEffect } from "react";
import adminApi from "../api/adminApi";
import { toast } from "react-toastify";
import {
    User,
    Mail,
    Phone,
    Home,
    CheckCircle,
    XCircle,
    X,
    Eye,
    Trash2,
    Building2,
    Loader2,
    RefreshCw,
    Search,
    Clock, // Assuming Clock is needed for pending status, based on Icon = isApproved ? CheckCircle : isPending ? Clock : XCircle;
} from "lucide-react";

// --- Configuration ---
const API_URL = import.meta.env.VITE_API_BASE_URL;

// Helper function (if needed, place here)
// const formatDate = (dateString) => { ... };

const StatusTag = ({ status }) => {
    // Map backend boolean/status to frontend tag style
    const isApproved = status === true || status === "approved";
    const isPending = status === "pending";

    const styles = isApproved
        ? "bg-emerald-50 text-emerald-600 border border-emerald-200"
        : isPending
            ? "bg-amber-50 text-amber-600 border border-amber-200"
            : "bg-rose-50 text-rose-600 border border-rose-200";

    const label = isApproved
        ? "Approved"
        : isPending
            ? "Pending Review"
            : "Rejected";

    const Icon = isApproved ? CheckCircle : isPending ? Clock : XCircle;

    return (
        <span className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold tracking-wide shadow-sm ${styles}`}>
            <Icon className="w-3.5 h-3.5" />
            {label}
        </span>
    );
};

const BuilderProjects = () => {
    const [ownersData, setOwnersData] = useState([]);
    const [loading, setLoading] = useState(true);
    const [searchTerm, setSearchTerm] = useState("");

    const [isRejectModalOpen, setIsRejectModalOpen] = useState(false);
    const [rejectingProject, setRejectingProject] = useState(null);
    const [rejectionReason, setRejectionReason] = useState("");

    const fetchOwnersWithProjects = async () => {
        try {
            setLoading(true);
            const { data } = await adminApi.get(`/api/users/owners-projects`);

            const mappedData = data.data.map(owner => ({
                ...owner,
                id: owner._id,
                projects: owner.projects.map(p => ({
                    ...p,
                    id: p._id,
                    title: p.title,
                    location: p.address?.city || 'N/A',
                    price: `₹${(p.price || 0).toLocaleString('en-IN')}`,
                    status: p.isApproved === false ? 'rejected' : p.isApproved === true ? 'approved' : 'pending'
                }))
            }));

            setOwnersData(mappedData);
            setLoading(false);
        } catch (error) {
            console.error("API Error:", error);
            setLoading(false);
            toast.error("Failed to fetch data.");
        }
    };

    const openRejectModal = (ownerId, projectId) => {
        setRejectingProject({ ownerId, projectId });
        setRejectionReason("");
        setIsRejectModalOpen(true);
    };

    const submitRejection = async () => {
        if (!rejectionReason.trim()) {
            return toast.error("Rejection reason is required");
        }

        const { ownerId, projectId } = rejectingProject;

        try {
            await adminApi.put(`/api/properties/disapprove/${projectId}`, {
                rejectionReason: rejectionReason.trim()
            });

            toast.success("Project rejected.");
            setIsRejectModalOpen(false);
            setRejectingProject(null);

            setOwnersData(prevOwners => prevOwners.map(owner => {
                if (owner.id === ownerId) {
                    return {
                        ...owner,
                        projects: owner.projects.map(p => {
                            if (p.id === projectId) {
                                return { ...p, status: 'rejected', isApproved: false };
                            }
                            return p;
                        })
                    };
                }
                return owner;
            }));
        } catch (err) {
            toast.error(err.response?.data?.message || "Failed to reject project.");
        }
    };

    const handleProjectAction = async (ownerId, projectId, action) => {
        if (!projectId) return toast.error("Project ID missing.");

        if (action === 'reject') {
            openRejectModal(ownerId, projectId);
            return;
        }

        const endpoint =
            action === 'approve'
                ? `/api/properties/approve/${projectId}`
                : `/api/properties/delete/${projectId}`;

        if (action === 'delete') {
            if (!window.confirm("Permanently delete this project? This action cannot be undone.")) return;
        }

        try {
            if (action === 'delete') {
                await adminApi.delete(endpoint);
            } else {
                await adminApi.put(endpoint, {});
            }

            toast.success(`Project ${action}d successfully.`);

            setOwnersData(prevOwners => prevOwners.map(owner => {
                if (owner.id === ownerId) {
                    return {
                        ...owner,
                        projects: owner.projects.filter(p => action !== 'delete' || p.id !== projectId).map(p => {
                            if (p.id === projectId && action === 'approve') {
                                return { ...p, status: 'approved', isApproved: true };
                            }
                            return p;
                        })
                    };
                }
                return owner;
            }));
        } catch (err) {
            toast.error(err.response?.data?.message || `Failed to ${action} project.`);
        }
    };

    useEffect(() => {
        fetchOwnersWithProjects();
    }, []);

    const filteredOwners = ownersData.map(owner => {
        const searchRaw = searchTerm.toLowerCase();
        const ownerMatches = owner.name.toLowerCase().includes(searchRaw) || 
                             owner.company?.toLowerCase().includes(searchRaw);
        
        const matchedProjects = owner.projects.filter(p => 
            ownerMatches || 
            p.title.toLowerCase().includes(searchRaw) ||
            p.location.toLowerCase().includes(searchRaw)
        );
        
        return { ...owner, projects: matchedProjects };
    }).filter(owner => owner.projects.length > 0 || owner.name.toLowerCase().includes(searchTerm.toLowerCase()));

    if (loading) {
        return (
            <div className="min-h-screen flex flex-col justify-center items-center bg-gray-50/50">
                <Loader2 className="w-10 h-10 animate-spin text-indigo-600 mb-4" />
                <p className="text-gray-500 font-medium">Loading Builder Projects...</p>
            </div>
        );
    }

    return (
        <div className="p-4 sm:p-8 min-h-screen bg-gray-50/30 max-w-7xl mx-auto space-y-8">
            {/* Header Area */}
            <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
                <div>
                    <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-gray-900 flex items-center gap-2">
                        <Building2 className="w-8 h-8 text-indigo-600" />
                        Builder Projects
                    </h1>
                    <p className="text-sm text-gray-500 mt-1 ml-10">Review, approve, and manage active builder properties.</p>
                </div>
                
                <div className="flex flex-col sm:flex-row items-center gap-3 w-full sm:w-auto">
                    <div className="relative w-full sm:w-64">
                        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
                        <input
                            type="text"
                            placeholder="Search builder or project..."
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                            className="w-full pl-10 pr-4 py-2 bg-white border border-gray-200 rounded-xl text-sm focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 outline-none transition-all shadow-sm"
                        />
                    </div>
                    <button
                        onClick={fetchOwnersWithProjects}
                        className="flex items-center justify-center gap-2 px-5 py-2.5 bg-white border border-gray-200 hover:border-indigo-300 text-gray-700 hover:text-indigo-700 rounded-xl shadow-sm transition-all text-sm font-semibold w-full sm:w-auto"
                    >
                        <RefreshCw className="w-4 h-4" />
                        Reload Board
                    </button>
                </div>
            </div>

            {filteredOwners.length === 0 && !loading && (
                <div className="flex flex-col items-center justify-center p-16 bg-white border border-gray-200 border-dashed rounded-2xl shadow-sm">
                    {searchTerm ? (
                        <>
                            <Search className="w-16 h-16 text-gray-300 mb-4" />
                            <h3 className="text-xl font-semibold text-gray-700">No matches found</h3>
                            <p className="text-gray-500 mt-2 text-center max-w-md">Try adjusting your search query, or clear it to see all builder projects.</p>
                        </>
                    ) : (
                        <>
                            <Building2 className="w-16 h-16 text-gray-300 mb-4" />
                            <h3 className="text-xl font-semibold text-gray-700">No Builder Projects Found</h3>
                            <p className="text-gray-500 mt-2 text-center max-w-md">There are currently no owners with active building projects in the system. Check back later.</p>
                        </>
                    )}
                </div>
            )}

            <div className="space-y-12">
                {filteredOwners.map((owner) => (
                    <div key={owner.id} className="relative">
                        {/* Owner Header */}
                        <div className="flex flex-col lg:flex-row justify-between items-start lg:items-center bg-white px-6 py-5 rounded-2xl border border-gray-200 shadow-sm mb-6 z-10 relative">
                            <div className="flex items-center gap-4">
                                <div className="w-12 h-12 rounded-full bg-indigo-50 border border-indigo-100 flex items-center justify-center text-indigo-700 flex-shrink-0">
                                    <span className="font-bold text-lg uppercase tracking-wider">{owner.name.charAt(0)}</span>
                                </div>
                                <div>
                                    <h2 className="text-lg font-bold text-gray-900 flex items-center gap-2">
                                        {owner.name}
                                        <span className="bg-gray-100 text-gray-600 px-2.5 py-0.5 rounded-full text-xs font-semibold">
                                            {owner.projects.length} {owner.projects.length === 1 ? 'Project' : 'Projects'}
                                        </span>
                                    </h2>
                                    <p className="text-sm text-gray-500 flex items-center gap-1.5 mt-0.5">
                                        <Building2 className="w-3.5 h-3.5" /> {owner.company || 'Independent Builder'}
                                    </p>
                                </div>
                            </div>
                            
                            {/* Contact Details inline */}
                            <div className="flex flex-wrap items-center gap-4 mt-4 lg:mt-0 text-gray-600 text-sm font-medium">
                                <a href={`mailto:${owner.email}`} className="flex items-center gap-1.5 hover:text-indigo-600 transition-colors">
                                    <div className="p-1.5 bg-gray-50 rounded-lg"><Mail className="w-4 h-4" /></div>
                                    {owner.email}
                                </a>
                                {owner.phone && (
                                    <>
                                        <span className="text-gray-300 hidden sm:block">|</span>
                                        <a href={`tel:${owner.phone}`} className="flex items-center gap-1.5 hover:text-indigo-600 transition-colors">
                                            <div className="p-1.5 bg-gray-50 rounded-lg"><Phone className="w-4 h-4" /></div>
                                            {owner.phone}
                                        </a>
                                    </>
                                )}
                            </div>
                        </div>

                        {/* Projects Grid */}
                        {owner.projects.length > 0 ? (
                            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
                                {owner.projects.map((p) => (
                                    <div
                                        key={p.id}
                                        className="group bg-white rounded-2xl overflow-hidden border border-gray-200 shadow-sm hover:shadow-xl hover:border-gray-300 transition-all duration-300 flex flex-col"
                                    >
                                        {/* Image Section */}
                                        <div className="relative aspect-[4/3] bg-gray-100 overflow-hidden">
                                            <img
                                                src={p.images?.[0] || 'https://images.unsplash.com/photo-1516132431682-12f5a65a3962?auto=format&fit=crop&w=800&q=80'}
                                                className="w-full h-full object-cover transition-transform duration-500 group-hover:scale-105"
                                                alt={p.title}
                                                onError={(e) => { e.target.src = 'https://images.unsplash.com/photo-1560518883-ce09059eeffa?auto=format&fit=crop&w=800&q=80' }}
                                            />
                                            {/* Floating Status Tag */}
                                            <div className="absolute top-3 right-3 z-10">
                                                <StatusTag status={p.status} />
                                            </div>
                                            {/* Gradient overlay to make text pop if added over image */}
                                            <div className="absolute inset-0 bg-gradient-to-t from-gray-900/60 via-transparent to-transparent opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none" />
                                        </div>

                                        {/* Content Section */}
                                        <div className="p-5 flex flex-col flex-grow">
                                            <div className="flex-grow">
                                                <h4 className="text-base font-bold text-gray-900 leading-tight mb-2 line-clamp-2">
                                                    {p.title}
                                                </h4>
                                                
                                                <div className="flex items-center gap-1.5 text-gray-500 text-sm mb-4 bg-gray-50 w-fit px-2 py-1 rounded-md">
                                                    <Home className="w-3.5 h-3.5 flex-shrink-0" />
                                                    <span className="truncate max-w-[180px]">{p.location}</span>
                                                </div>

                                                <div className="flex items-end justify-between mt-auto mb-5">
                                                    <div>
                                                        <p className="text-xs text-gray-500 uppercase tracking-widest font-semibold mb-0.5">Price</p>
                                                        <p className="text-xl font-extrabold text-indigo-700">{p.price}</p>
                                                    </div>
                                                </div>
                                            </div>

                                            {/* Footer Actions */}
                                            <div className="pt-4 border-t border-gray-100 flex items-center justify-between gap-2 mt-auto">
                                                {/* Left Action: Primary Action Split */}
                                                <div className="flex-1 flex gap-2">
                                                    {p.status !== "approved" && (
                                                        <button
                                                            onClick={() => handleProjectAction(owner.id, p.id, 'approve')}
                                                            className="flex-1 flex items-center justify-center gap-1.5 py-2 px-3 bg-emerald-600 hover:bg-emerald-700 text-white rounded-xl text-sm font-semibold transition-colors shadow-sm"
                                                            title="Approve Project"
                                                        >
                                                            <CheckCircle className="w-4 h-4" />
                                                            Approve
                                                        </button>
                                                    )}

                                                    {p.status !== "rejected" && (
                                                        <button
                                                            onClick={() => handleProjectAction(owner.id, p.id, 'reject')}
                                                            className={`flex items-center justify-center gap-1.5 py-2 px-3 border transition-colors rounded-xl text-sm font-semibold shadow-sm ${p.status === 'approved' ? 'flex-1 border-rose-200 text-rose-600 hover:bg-rose-50' : 'flex-[0.6] bg-rose-600 hover:bg-rose-700 text-white border-transparent'}`}
                                                            title="Reject Project"
                                                        >
                                                            <XCircle className="w-4 h-4" />
                                                            {p.status === 'approved' ? 'Revoke' : 'Reject'}
                                                        </button>
                                                    )}
                                                </div>

                                                {/* Right Action: Delete */}
                                                <button
                                                    onClick={() => handleProjectAction(owner.id, p.id, 'delete')}
                                                    className="flex items-center justify-center p-2.5 text-gray-400 hover:text-rose-600 hover:bg-rose-50 rounded-xl transition-colors border border-transparent hover:border-rose-100"
                                                    title="Permanently Delete Project"
                                                >
                                                    <Trash2 className="w-4.5 h-4.5" />
                                                </button>
                                            </div>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        ) : (
                            <div className="text-center p-8 bg-gray-50/50 rounded-2xl border border-dashed border-gray-200 mt-2">
                                <p className="text-gray-500 font-medium">No projects listed by this builder yet.</p>
                            </div>
                        )}
                    </div>
                ))}
            </div>

            {/* Rejection Modal */}
            {isRejectModalOpen && (
                <div className="fixed inset-0 z-50 flex items-center justify-center bg-gray-900/60 backdrop-blur-sm p-4">
                    <div className="bg-white rounded-2xl shadow-2xl w-full max-w-lg overflow-hidden transform transition-all">
                        <div className="px-6 py-5 border-b border-gray-100 flex justify-between items-center">
                            <div className="flex items-center gap-3">
                                <div className="p-2 bg-rose-100 text-rose-600 rounded-full">
                                    <XCircle className="w-5 h-5" />
                                </div>
                                <div>
                                    <h3 className="text-lg font-bold text-gray-900">Reject Property</h3>
                                    <p className="text-xs text-gray-500 font-medium mt-0.5">Please provide a reason for the builder</p>
                                </div>
                            </div>
                            <button 
                                onClick={() => setIsRejectModalOpen(false)}
                                className="p-2 text-gray-400 hover:bg-gray-100 hover:text-gray-600 rounded-full transition-colors"
                            >
                                <X className="w-5 h-5" />
                            </button>
                        </div>
                        <div className="p-6 bg-gray-50/50">
                            <label className="block text-sm font-semibold text-gray-700 mb-2">
                                Detail the issue <span className="text-rose-500">*</span>
                            </label>
                            <textarea
                                className="w-full border border-gray-200 rounded-xl p-4 focus:ring-4 focus:ring-rose-500/10 focus:border-rose-500 outline-none transition-all shadow-sm resize-none text-sm"
                                placeholder="E.g., Low quality images, invalid pricing, missing RERA details..."
                                value={rejectionReason}
                                onChange={(e) => setRejectionReason(e.target.value)}
                                rows={4}
                                maxLength={500}
                                autoFocus
                            />
                            <div className="flex justify-between items-center mt-2 px-1">
                                <p className="text-xs text-rose-600 font-medium opacity-0 flex items-center gap-1.5 transition-opacity {...(!rejectionReason.trim() && { style: { opacity: 1 }})}">
                                    <span className="w-1.5 h-1.5 rounded-full bg-rose-500" /> Required
                                </p>
                                <p className="text-xs text-gray-400 font-medium">
                                    <span className={rejectionReason.length > 450 ? 'text-amber-500' : ''}>{rejectionReason.length}</span> / 500
                                </p>
                            </div>
                        </div>
                        <div className="px-6 py-5 border-t border-gray-100 flex justify-end gap-3 bg-white">
                            <button
                                onClick={() => setIsRejectModalOpen(false)}
                                className="px-5 py-2.5 bg-white border border-gray-200 text-gray-700 font-semibold rounded-xl text-sm hover:bg-gray-50 hover:border-gray-300 transition-colors shadow-sm"
                            >
                                Cancel
                            </button>
                            <button
                                onClick={submitRejection}
                                disabled={!rejectionReason.trim()}
                                className="px-5 py-2.5 bg-rose-600 outline-none focus:ring-4 focus:ring-rose-500/20 text-white font-semibold rounded-xl text-sm hover:bg-rose-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all shadow-sm flex items-center gap-2"
                            >
                                <XCircle className="w-4 h-4" /> Send Rejection
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default BuilderProjects;