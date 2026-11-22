package dev.difme.core.common.process;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Loan origination input (ADR-025), built by process-gateway from the BPMN process variables. Amounts in paise. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record LoanApplication(String processInstanceId, String businessKey, String applicantId, long fineractClientId, long amountMinor,
                              int termMonths, String purpose) {}
