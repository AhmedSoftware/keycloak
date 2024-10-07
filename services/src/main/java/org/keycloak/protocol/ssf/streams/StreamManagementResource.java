package org.keycloak.protocol.ssf.streams;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.annotation.JsonValue;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.PATCH;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import org.jboss.resteasy.reactive.NoCache;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.ssf.set.SecurityEventToken;
import org.keycloak.protocol.ssf.streams.StreamRepresentation.AbstractDeliveryMethod;
import org.keycloak.protocol.ssf.subjects.SubjectId;
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;

import java.net.URI;
import java.util.List;

@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public class StreamManagementResource {

    private final KeycloakSession session;
    private final RealmModel realm;
    private final AdminPermissionEvaluator auth;
    private final AdminEventBuilder adminEvent;

    private final SsfStreamProvider streamProvider;

    public StreamManagementResource(KeycloakSession session, RealmModel realm, AdminPermissionEvaluator auth, AdminEventBuilder adminEvent) {
        this.session = session;
        this.realm = realm;
        this.auth = auth;
        this.adminEvent = adminEvent;

        this.streamProvider = new SsfStreamProvider();
    }

    /**
     * 7.1.1.1. Creating a Stream
     * See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-7.1.1.1
     * @param createRequest
     * @param uriInfo
     * @return
     */
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @POST
    @Path("/streams")
    public Response createStream(@Context UriInfo uriInfo) {

        // TODO check user permissions streams:create
        auth.realm().requireViewRealm();

        CreateStreamRequest createRequest = new CreateStreamRequest();

        StreamRepresentation stream = streamProvider.createStream(session, realm, createRequest);
        String id = stream.getId();
        URI createdLocation = uriInfo.getAbsolutePathBuilder().path(id).build();

        // Errors are signaled with HTTP status codes as follows:
        /*
        400	if the request cannot be parsed
401	if authorization failed or it is missing
403	if the Event Receiver is not allowed to create a stream
409	if the Transmitter does not support multiple streams per Receiver
         */

        return Response.status(Response.Status.CREATED)
                .location(createdLocation)
                .entity(stream).build();
    }

    /**
     * 7.1.1.2. Reading Stream configurations
     * See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-7.1.1.3
     * @return
     */
    @GET
    @Path("/streams")
    public Response findStreams(@QueryParam("stream_id") String streamId) {

        // TODO check user permissions streams:view
        auth.realm().requireViewRealm();

        if (streamId != null) {
            /*
            7.1.1.2. Reading a Stream's Configuration
            See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-7.1.1.2
             */
            StreamRepresentation stream = streamProvider.findStream(session, realm, streamId);
            if (stream == null) {
                return Response.status(Response.Status.NOT_FOUND).build();
            }
            return Response.ok(stream).build();
        }

        List<StreamRepresentation> streams = streamProvider.findStreams(session, realm);

        // Errors are signaled with HTTP status codes as follows:
        /*
        401	if authorization failed or it is missing
403	if the Event Receiver is not allowed to read the stream configuration
404	if there is no Event Stream with the given "stream_id" for this Event Receiver
         */

        return Response.ok(streams).build();
    }

    /**
     * 7.1.1.3. Updating a Stream's Configuration
     * See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-7.1.1.3
     * @param updateRequest
     * @param uriInfo
     * @return
     */
    @PATCH
    @Path("/streams")
    public Response updateStream(UpdateStreamRequest updateRequest, @Context UriInfo uriInfo) {

        // TODO check user permissions streams:update
        auth.realm().requireViewRealm();

        StreamRepresentation updated = streamProvider.updateStream(session, realm, updateRequest);

        // Pending conditions or errors are signaled with HTTP status codes as follows:
        /*
        202	if the update request has been accepted, but not processed. Receiver MAY try the same request later to get processing result.
400	if the request body cannot be parsed, a Transmitter-Supplied property is incorrect, or if the request is otherwise invalid
401	if authorization failed or it is missing
403	if the Event Receiver is not allowed to update the stream configuration
404	if there is no Event Stream with the given "stream_id" for this Event Receiver
         */

        return Response.ok().entity(updated).build();
    }

    /**
     * 7.1.1.4. Replace a Stream's Configuration
     * See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-7.1.1.4
     * @param updateRequest
     * @param uriInfo
     * @return
     */
    @PUT
    @Path("/streams")
    public Response replaceStream(ReplaceStreamRequest updateRequest, @Context UriInfo uriInfo) {

        // TODO check user permissions streams:update
        auth.realm().requireViewRealm();

        StreamRepresentation replaced = streamProvider.updateStream(session, realm, updateRequest);

        // Pending conditions or errors are signaled with HTTP status codes as follows:
        /*
        202	if the replace request has been accepted, but not processed. Receiver MAY try the same request later in order to get processing result.
400	if the request body cannot be parsed, a Transmitter-Supplied property is incorrect, or if the request is otherwise invalid
401	if authorization failed or it is missing
403	if the Event Receiver is not allowed to replace the stream configuration
404	if there is no Event Stream with the given "stream_id" for this Event Receiver
         */

        return Response.ok().entity(replaced).build();
    }

    /**
     * 7.1.1.5. Deleting a Stream
     *
     * See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-7.1.1.5
     * @param streamId
     * @return
     */
    @DELETE
    @NoCache
    @Path("/streams")
    public Response deleteStream(@QueryParam("stream_id") String streamId) {

        checkRequiredParameter(streamId, "stream_id");

        // TODO check user permissions streams:update
        auth.realm().requireViewRealm();

        boolean deleted = streamProvider.deleteStream(session, realm, streamId);

        /**
         * Errors are signaled with HTTP status codes as follows:
         *
         * Table 5: Delete Stream Errors
         * 401	if authorization failed or it is missing
         * 403	if the Event Receiver is not allowed to delete the stream
         * 404	if there is no Event Stream with the given "stream_id" for this Event Receiver
         */

        return Response.noContent().build();
    }

    @POST
    @Path("/streams/{streamId}/poll")
    public Response pollStreamEvents(@PathParam("streamId") String streamId) {

        auth.realm().requireViewRealm();

        List<SecurityEventToken> tokens = streamProvider.retrieveEvents(session, realm, streamId);

        return Response.ok().entity(tokens).build();
    }

    static void checkRequiredParameter(Object paramValue, String paramName) {
        if (paramValue == null) {
            throw new WebApplicationException(
                    Response.status(Response.Status.BAD_REQUEST)
                            .entity(paramName + " parameter is mandatory")
                            .build()
            );
        }
    }

    /**
     * 7.1.2.1. Reading a Stream's Status
     * See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-7.1.2.1
     * @param streamId
     * @return
     */
    @GET
    @Path("/status")
    public Response status(@QueryParam("stream_id") String streamId) {

        checkRequiredParameter(streamId, "stream_id");

        // TODO check user permissions streams:update
        auth.realm().requireViewRealm();

        StreamStatusRepresentation statusRep = streamProvider.getStreamStatus(session, realm, streamId);

        // Errors are signaled with HTTP status codes as follows:
        /*
        401	if authorization failed or it is missing
403	if the Event Receiver is not allowed to read the stream status
404	if there is no Event Stream with the given "stream_id" for this Event Receiver
         */

        return Response.ok().entity(statusRep).build();
    }

    /**
     * 7.1.2.2. Updating a Stream's Status
     *
     * See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-7.1.2.2
     *
     * @param updateStatusRequest
     * @return
     */
    @POST
    @Path("/status")
    public Response updateStatus(UpdateStatusRequest updateStatusRequest) {

        checkRequiredParameter(updateStatusRequest.getId(), "stream_id");
        checkRequiredParameter(updateStatusRequest.getStatus(), "status");

        // TODO check user permissions stream-status:update
        auth.realm().requireViewRealm();
        StreamStatusRepresentation newStatus = streamProvider.updateStreamStatus(updateStatusRequest);

        // Errors are signaled with HTTP status codes as follows:
        /*
        202	if the update request has been accepted, but not processed. Receiver MAY try the same request later in order to get processing result.
400	if the request body cannot be parsed or if the request is otherwise invalid
401	if authorization failed or it is missing
403	if the Event Receiver is not allowed to update the stream status
404	if there is no Event Stream with the given "stream_id" for this Event Receiver
         */

        // If a Receiver makes a request to update a stream status, and the Transmitter is unable to decide whether or not to complete the request, then the Transmitter MUST respond with a 202 status code.

        return Response.ok().entity(newStatus).build();
    }

    /**
     * 7.1.3.1. Adding a Subject to a Stream
     * See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-7.1.3.1
     * @return
     */
    @POST
    @Path("/subjects:add")
    public Response addSubject(AddSubjectRequest addSubjectRequest) {

        checkRequiredParameter(addSubjectRequest.getStreamId(), "stream_id");
        checkRequiredParameter(addSubjectRequest.getSubject(), "subject");

        auth.realm().requireViewRealm();

        boolean added = streamProvider.addStreamSubject(session, realm, addSubjectRequest);

        return Response.ok().build();
    }

    /**
     * 7.1.3.2. Removing a Subject
     * See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-7.1.3.2
     */
    @POST
    @NoCache
    @Path("/subjects:remove")
    public Response removeSubject(RemoveSubjectRequest removeSubjectRequest) {

        checkRequiredParameter(removeSubjectRequest.getStreamId(), "stream_id");
        checkRequiredParameter(removeSubjectRequest.getSubject(), "subject");

        auth.realm().requireViewRealm();

        boolean removed = streamProvider.removeSubject(session, realm, removeSubjectRequest);

        // Errors are signaled with HTTP status codes as follows:
        /*
        400	if the request body cannot be parsed or if the request is otherwise invalid
401	if authorization failed or it is missing
403	if the Event Receiver is not allowed to remove this particular subject, or not allowed to remove in general
404	if there is no Event Stream with the given "stream_id" for this Event Receiver, or if the subject is not recognized by the Event Transmitter. The Event Transmitter may choose to stay silent in this second case and respond with "204"
429	if the Event Receiver is sending too many requests in a given amount of time
         */

        return Response.noContent().build();
    }

    /**
     * 7.1.4.2. Triggering a Verification Event.
     * See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-7.1.4.2
     * @return
     */
    @POST
    @Path("/verify")
    public Response verify(VerificationRequest verificationRequest) {

        checkRequiredParameter(verificationRequest.getStreamId(), "stream_id");

        auth.realm().requireViewRealm();

        // Errors are signaled with HTTP status codes as follows:
        /*
        400	if the request body cannot be parsed or if the request is otherwise invalid
401	if authorization failed or it is missing
404	if there is no Event Stream with the given "stream_id" for this Event Receiver
429	if the Event Receiver is sending too many requests in a given amount of time; see related "min_verification_interval" in Section 7.1.1
         */

        streamProvider.addVerificationEvent(session, realm, verificationRequest);

        return Response.noContent().build();
    }

    public static class VerificationRequest {
        /**
         * REQUIRED. A string identifying the stream to which the subject is being added.
         */
        @JsonProperty("stream_id")
        private String streamId;

        /**
         * OPTIONAL. An arbitrary string that the Event Transmitter MUST echo back to the Event Receiver in the Verification Event's payload. Event Receivers MAY use the value of this parameter to correlate a Verification Event with a verification request. If the Verification Event is initiated by the Transmitter then this parameter MUST not be set.
         */
        @JsonProperty("state")
        private String state;

        public String getStreamId() {
            return streamId;
        }

        public void setStreamId(String streamId) {
            this.streamId = streamId;
        }

        public String getState() {
            return state;
        }

        public void setState(String state) {
            this.state = state;
        }
    }

    public static class RemoveSubjectRequest {
        /**
         * REQUIRED. A string identifying the stream to which the subject is being added.
         */
        @JsonProperty("stream_id")
        private String streamId;

        /**
         * REQUIRED. A Subject claim identifying the subject to be added.
         */
        @JsonProperty("subject")
        private SubjectId subject;

        public String getStreamId() {
            return streamId;
        }

        public void setStreamId(String streamId) {
            this.streamId = streamId;
        }

        public SubjectId getSubject() {
            return subject;
        }

        public void setSubject(SubjectId subject) {
            this.subject = subject;
        }
    }

    public static class AddSubjectRequest {

        /**
         * REQUIRED. A string identifying the stream to which the subject is being added.
         */
        @JsonProperty("stream_id")
        private String streamId;

        /**
         * REQUIRED. A Subject claim identifying the subject to be added.
         */
        @JsonProperty("subject")
        private SubjectId subject;

        /**
         * OPTIONAL. A boolean value; when true, it indicates that the Event Receiver has verified the Subject claim. When false, it indicates that the Event Receiver has not verified the Subject claim. If omitted, Event Transmitters SHOULD assume that the subject has been verified.
         */
        @JsonProperty("verified")
        private Boolean verified;

        public String getStreamId() {
            return streamId;
        }

        public void setStreamId(String streamId) {
            this.streamId = streamId;
        }

        public SubjectId getSubject() {
            return subject;
        }

        public void setSubject(SubjectId subject) {
            this.subject = subject;
        }

        public Boolean getVerified() {
            return verified;
        }

        public void setVerified(Boolean verified) {
            this.verified = verified;
        }
    }

    public static class UpdateStatusRequest extends StreamStatusRepresentation{
    }

    public static class StreamStatusRepresentation {

        @JsonProperty("stream_id")
        private String id;

        @JsonProperty("status")
        private StreamStatus status;

        @JsonProperty("reason")
        private String reason;

        public String getId() {
            return id;
        }

        public void setId(String id) {
            this.id = id;
        }

        public StreamStatus getStatus() {
            return status;
        }

        public void setStatus(StreamStatus status) {
            this.status = status;
        }

        public String getReason() {
            return reason;
        }

        public void setReason(String reason) {
            this.reason = reason;
        }
    }

    public enum StreamStatus {

        /**
         * The Transmitter MUST transmit events over the stream, according to the stream's configured delivery method.
         */
        ENABLED("enabled"),

        /**
         * The Transmitter MUST NOT transmit events over the stream. The Transmitter will hold any events it would have transmitted while paused, and SHOULD transmit them when the stream's status becomes "enabled". If a Transmitter holds successive events that affect the same Subject Principal, then the Transmitter MUST make sure that those events are transmitted in the order of time that they were generated OR the Transmitter MUST send only the last events that do not require the previous events affecting the same Subject Principal to be processed by the Receiver, because the previous events are either cancelled by the later events or the previous events are outdated.
         */
        PAUSED("paused"),

        /**
         * The Transmitter MUST NOT transmit events over the stream and will not hold any events for later transmission.
         */
        DISABLED("disabled")
        ;

        private final String value;

        StreamStatus(String value) {
            this.value = value;
        }

        @JsonCreator
        public static StreamStatus fromString(String value) {
            return StreamStatus.valueOf(value.toUpperCase());
        }

        @JsonValue
        public String getValue() {
            return value;
        }
    }

    public static class UpdateStreamRequest extends StreamRepresentation {
    }

    public static class ReplaceStreamRequest extends UpdateStreamRequest {
    }

    public static class CreateStreamRequest {

        /**
         * Receiver-Supplied, OPTIONAL. An array of URIs identifying the set of events that the Receiver requested. A Receiver SHOULD request only the events that it understands and it can act on. This is configurable by the Receiver. A Transmitter MUST ignore any array values that it does not understand. This array SHOULD NOT be empty.
         */
        @JsonProperty("events_requested")
        private List<URI> eventsRequested;

        /**
         * Receiver-Supplied, OPTIONAL. A JSON object containing a set of name/value pairs specifying configuration parameters for the SET delivery method. The actual delivery method is identified by the special key "method" with the value being a URI as defined in Section 10.3.1. The value of the "delivery" field contains two sub-fields:
         */
        @JsonProperty("delivery")
        @JsonTypeInfo(use = JsonTypeInfo.Id.NAME, property = "method")
        private AbstractDeliveryMethod delivery;

        /**
         * Receiver-Supplied, OPTIONAL. A string that describes the properties of the stream. This is useful in multi-stream systems to identify the stream for human actors. The transmitter MAY truncate the string beyond an allowed max length.
         */
        @JsonProperty("description")
        private String description;

        public List<URI> getEventsRequested() {
            return eventsRequested;
        }

        public void setEventsRequested(List<URI> eventsRequested) {
            this.eventsRequested = eventsRequested;
        }

        public AbstractDeliveryMethod getDelivery() {
            return delivery;
        }

        public void setDelivery(AbstractDeliveryMethod delivery) {
            this.delivery = delivery;
        }

        public String getDescription() {
            return description;
        }

        public void setDescription(String description) {
            this.description = description;
        }
    }

}
