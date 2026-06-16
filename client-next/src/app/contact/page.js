import ContactContent from "./ContactContent";

export const metadata = {
    title: "Contact Us",
    description:
        "Get in touch with DealDirect. Whether you're a buyer, seller, or just have a question — our team is here to help you navigate your property journey.",
    openGraph: {
        title: "Contact DealDirect — We're Here to Help",
        description: "Reach out to our team for support with property listings, partnerships, or general inquiries.",
        url: 'https://dealdirect.in/contact',
    },
    alternates: {
        canonical: 'https://dealdirect.in/contact',
    },
};

export default function ContactPage() {
    return <ContactContent />;
}
