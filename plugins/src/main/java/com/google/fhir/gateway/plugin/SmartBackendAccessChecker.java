/*
 * Copyright 2021-2024 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.google.fhir.gateway.plugin;

import ca.uhn.fhir.context.FhirContext;
import ca.uhn.fhir.rest.api.RequestTypeEnum;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;
import com.google.fhir.gateway.BundlePatients;
import com.google.fhir.gateway.FhirUtil;
import com.google.fhir.gateway.HttpFhirClient;
import com.google.fhir.gateway.JwtUtil;
import com.google.fhir.gateway.interfaces.*;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.Set;
import javax.inject.Named;
import org.hl7.fhir.instance.model.api.IIdType;
import org.hl7.fhir.r4.model.Bundle;
import org.hl7.fhir.r4.model.Reference;
import org.hl7.fhir.r4.model.ResourceType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SmartBackendAccessChecker implements AccessChecker {

  private static final Logger logger = LoggerFactory.getLogger(PatientAccessChecker.class);

  private final PatientFinder patientFinder;
  private final FhirContext fhirContext;

  private final SmartScopeChecker smartScopeChecker;

  private SmartBackendAccessChecker(
      FhirContext fhirContext, PatientFinder patientFinder, SmartScopeChecker smartScopeChecker) {
    this.fhirContext = fhirContext;
    this.patientFinder = patientFinder;
    Preconditions.checkNotNull(patientFinder);
    Preconditions.checkNotNull(smartScopeChecker);
    Preconditions.checkNotNull(fhirContext);
    this.smartScopeChecker = smartScopeChecker;
  }

  @Override
  public AccessDecision checkAccess(RequestDetailsReader requestDetails) {
    if (requestDetails.getRequestType() == RequestTypeEnum.POST
        && requestDetails.getResourceName() == null) {
      return processBundle(requestDetails);
    }
    switch (requestDetails.getRequestType()) {
      case GET:
        return processGet(requestDetails);
      case POST:
        return processPost(requestDetails);
      case PUT:
        // TODO(https://github.com/google/fhir-gateway/issues/88): Support update as create
        // operation
      case PATCH:
        return processUpdate(requestDetails);
      case DELETE:
        return processDelete(requestDetails);
      default:
        return NoOpAccessDecision.accessDenied();
    }
  }

  private AccessDecision processGet(RequestDetailsReader requestDetails) {
    if (requestDetails.getResourceName() == null) {
      return NoOpAccessDecision.accessDenied();
    }
    // This operation corresponds to the read/vread/history operations on instance
    if (requestDetails.getId() != null) {
      return processRead(requestDetails);
    }
    return processSearch(requestDetails);
  }

  private AccessDecision processPost(RequestDetailsReader requestDetails) {
    // TODO(https://github.com/google/fhir-gateway/issues/87): Add support for search in post
    return processCreate(requestDetails);
  }

  private AccessDecision processRead(RequestDetailsReader requestDetails) {
    return new NoOpAccessDecision(
        smartScopeChecker.hasPermission(
            requestDetails.getResourceName(), SmartFhirScope.Permission.READ));
  }

  private AccessDecision processSearch(RequestDetailsReader requestDetails) {
    return new NoOpAccessDecision(
        smartScopeChecker.hasPermission(
            requestDetails.getResourceName(), SmartFhirScope.Permission.SEARCH));
  }

  private AccessDecision processCreate(RequestDetailsReader requestDetails) {
    // This AccessChecker does not accept new patients.
    if (FhirUtil.isSameResourceType(requestDetails.getResourceName(), ResourceType.Patient)) {
      return NoOpAccessDecision.accessDenied();
    }
    return new NoOpAccessDecision(
        smartScopeChecker.hasPermission(
            requestDetails.getResourceName(), SmartFhirScope.Permission.CREATE));
  }

  private AccessDecision processUpdate(RequestDetailsReader requestDetails) {
    if (FhirUtil.isSameResourceType(requestDetails.getResourceName(), ResourceType.Patient)) {
      return checkPatientAccessInUpdate(requestDetails);
    }
    return checkNonPatientAccessInUpdate(requestDetails, requestDetails.getRequestType());
  }

  private AccessDecision processDelete(RequestDetailsReader requestDetails) {
    // This AccessChecker does not allow deletion of Patient resource
    if (FhirUtil.isSameResourceType(requestDetails.getResourceName(), ResourceType.Patient)) {
      return NoOpAccessDecision.accessDenied();
    }
    // TODO(https://github.com/google/fhir-access-proxy/issues/63):Support direct resource deletion.
    return new NoOpAccessDecision(
        smartScopeChecker.hasPermission(
            requestDetails.getResourceName(), SmartFhirScope.Permission.DELETE));
  }

  private AccessDecision checkNonPatientAccessInUpdate(
      RequestDetailsReader requestDetails, RequestTypeEnum updateMethod) {
    // We do not allow direct resource PUT/PATCH, so Patient ID must be returned
    Set<String> patientIds;
    if (updateMethod == RequestTypeEnum.PATCH) {
      patientIds =
          patientFinder.findPatientsInPatch(requestDetails, requestDetails.getResourceName());
      if (patientIds.isEmpty()) {
        return NoOpAccessDecision.accessGranted();
      }
    }
    return new NoOpAccessDecision(
        smartScopeChecker.hasPermission(
            requestDetails.getResourceName(), SmartFhirScope.Permission.UPDATE));
  }

  private AccessDecision checkPatientAccessInUpdate(RequestDetailsReader requestDetails) {
    String patientId = FhirUtil.getIdOrNull(requestDetails);
    if (patientId == null) {
      // This is an invalid PUT request; note we are not supporting "conditional updates".
      logger.error("The provided Patient resource has no ID; denying access!");
      return NoOpAccessDecision.accessDenied();
    }
    return new NoOpAccessDecision(
        smartScopeChecker.hasPermission(
            ResourceType.Patient.name(), SmartFhirScope.Permission.UPDATE));
  }

  private AccessDecision processBundle(RequestDetailsReader requestDetails) {
    Bundle requestBundle = FhirUtil.parseRequestToBundle(fhirContext, requestDetails);
    BundlePatients patientsInBundle = patientFinder.findPatientsInBundle(requestBundle);

    if (patientsInBundle == null
        || patientsInBundle.areTherePatientToCreate()
        || !patientsInBundle.getDeletedPatients().isEmpty()) {
      return NoOpAccessDecision.accessDenied();
    }

    if (!patientsInBundle.getUpdatedPatients().isEmpty()) {
      return NoOpAccessDecision.accessDenied();
    }

    for (Bundle.BundleEntryComponent entryComponent : requestBundle.getEntry()) {
      if (!doesBundleElementHavePermission(entryComponent)) {
        return NoOpAccessDecision.accessDenied();
      }
    }
    return NoOpAccessDecision.accessGranted();
  }

  private boolean doesReferenceElementHavePermission(
      IIdType referenceElement, SmartFhirScope.Permission permission) {
    if (referenceElement.getResourceType() != null && referenceElement.hasIdPart()) {
      return smartScopeChecker.hasPermission(referenceElement.getResourceType(), permission);
    } else {
      return smartScopeChecker.hasPermission(referenceElement.getValue(), permission);
    }
  }

  private boolean doesBundleElementHavePermission(Bundle.BundleEntryComponent bundleEntry) {
    Bundle.BundleEntryRequestComponent bundleEntryRequest = bundleEntry.getRequest();
    try {
      switch (bundleEntryRequest.getMethod()) {
        case GET:
          if (bundleEntryRequest.getUrl() != null) {
            URI resourceUri = new URI(bundleEntryRequest.getUrl());
            IIdType referenceElement = new Reference(resourceUri.getPath()).getReferenceElement();
            return doesReferenceElementHavePermission(
                referenceElement, SmartFhirScope.Permission.READ);
          }
          break;
        case POST:
          if (bundleEntry.getResource().getResourceType() != null) {
            return smartScopeChecker.hasPermission(
                bundleEntry.getResource().getResourceType().name(),
                SmartFhirScope.Permission.CREATE);
          }
          // TODO(https://github.com/google/fhir-gateway/issues/87): Add support for search in post
          break;
        case PUT:
          if (bundleEntryRequest.getUrl() != null) {
            URI resourceUri = new URI(bundleEntryRequest.getUrl());
            IIdType referenceElement = new Reference(resourceUri.getPath()).getReferenceElement();
            return doesReferenceElementHavePermission(
                referenceElement, SmartFhirScope.Permission.UPDATE);
          }
          break;
        case PATCH:
          if (bundleEntryRequest.getUrl() != null) {
            URI resourceUri = new URI(bundleEntryRequest.getUrl());
            IIdType referenceElement = new Reference(resourceUri.getPath()).getReferenceElement();
            return doesReferenceElementHavePermission(
                referenceElement, SmartFhirScope.Permission.UPDATE);
          }
        case DELETE:
          if (bundleEntryRequest.getUrl() != null) {
            URI resourceUri = new URI(bundleEntryRequest.getUrl());
            IIdType referenceElement = new Reference(resourceUri.getPath()).getReferenceElement();
            return doesReferenceElementHavePermission(
                referenceElement, SmartFhirScope.Permission.DELETE);
          }
          break;
        default:
          return false;
      }
    } catch (URISyntaxException e) {
      logger.error(
          String.format("Error in parsing bundle request url %s", bundleEntryRequest.getUrl()));
    }
    return false;
  }

  @Named(value = "scope")
  static class Factory implements AccessCheckerFactory {

    @VisibleForTesting static final String SCOPES_CLAIM = "scope";

    private SmartScopeChecker getSmartFhirPermissionChecker(DecodedJWT jwt) {
      String scopesClaim = JwtUtil.getClaimOrDie(jwt, SCOPES_CLAIM);
      String[] scopes = scopesClaim.strip().split("\\s+");
      return new SmartScopeChecker(
          SmartFhirScope.extractSmartFhirScopesFromTokens(Arrays.asList(scopes)),
          SmartFhirScope.Principal.SYSTEM);
    }

    public AccessChecker create(
        DecodedJWT jwt,
        HttpFhirClient httpFhirClient,
        FhirContext fhirContext,
        PatientFinder patientFinder) {
      return new SmartBackendAccessChecker(fhirContext, patientFinder, getSmartFhirPermissionChecker(jwt));
    }
  }
}
